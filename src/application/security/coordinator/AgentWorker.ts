import { randomUUID } from "node:crypto";
import { ok, err, type Result } from "../../../domain/result.js";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type {
  ICentralBlackboard,
  TaskRecord,
  TaskClaim,
  TaskPriority,
} from "../../../domain/security/blackboard/types.js";
import type { IContextProjector } from "../../../domain/security/blackboard/contextProjection.js";
import type { BlackboardError } from "../../../domain/security/blackboard/errors.js";
import type { WorkerConfig, TaskExecutionHandler } from "./coordinatorTypes.js";

const PRIORITY_WEIGHTS: Record<TaskPriority, number> = {
  critical: 4,
  high: 3,
  normal: 2,
  low: 1,
};

export class AgentWorker {
  public readonly agentId: string;
  public readonly assessmentId: AssessmentId;
  public readonly capabilities: readonly string[];
  public readonly hostId: string;
  public readonly pid: number;
  private readonly blackboard: ICentralBlackboard;
  private readonly contextProjector: IContextProjector;
  private readonly taskHandler: TaskExecutionHandler;

  private readonly pollIntervalMs: number;
  private readonly leaseDurationMs: number;
  private readonly heartbeatIntervalMs: number;
  private readonly taskTimeoutMs: number;
  private readonly maxTaskCeilingRenewals: number;
  private readonly maxRetries: number;
  private readonly processStartTime: number;
  private readonly reaRunId: string;

  private running = false;
  private busy = false;
  private pollTimer: NodeJS.Timeout | null = null;
  private currentAbortController: AbortController | null = null;

  constructor(
    config: WorkerConfig,
    blackboard: ICentralBlackboard,
    contextProjector: IContextProjector,
    taskHandler: TaskExecutionHandler,
  ) {
    this.agentId = config.agentId;
    this.assessmentId = config.assessmentId;
    this.capabilities = [...config.capabilities];
    this.hostId = config.hostId ?? "localhost";
    this.pid = config.pid ?? process.pid;
    this.blackboard = blackboard;
    this.contextProjector = contextProjector;
    this.taskHandler = taskHandler;

    this.pollIntervalMs = config.pollIntervalMs ?? 50;
    this.leaseDurationMs = config.leaseDurationMs ?? 3000;
    this.heartbeatIntervalMs = config.heartbeatIntervalMs ?? 500;
    this.taskTimeoutMs = config.taskTimeoutMs ?? 10_000;
    this.maxTaskCeilingRenewals = config.maxTaskCeilingRenewals ?? 5;
    this.maxRetries = config.maxRetries ?? 3;

    this.processStartTime = Date.now();
    this.reaRunId = randomUUID();
  }

  public isBusy(): boolean {
    return this.busy;
  }

  public isRunning(): boolean {
    return this.running;
  }

  public async start(): Promise<Result<void, BlackboardError>> {
    this.running = true;

    // 1. Register with blackboard agent registry
    const regRes = await this.blackboard.agents.register({
      agent_id: this.agentId,
      assessment_id: this.assessmentId,
      capabilities: this.capabilities,
      host_id: this.hostId,
      pid: this.pid,
      status: "idle",
      heartbeat_at: Date.now(),
      registered_at: Date.now(),
    });
    if (!regRes.ok) {
      this.running = false;
      return regRes;
    }

    // 2. Start autonomous polling loop
    this.scheduleNextPoll();
    return ok(undefined);
  }

  public async stop(): Promise<void> {
    this.running = false;
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }

    if (this.currentAbortController) {
      this.currentAbortController.abort();
      this.currentAbortController = null;
    }

    await this.blackboard.agents.updateStatus(this.assessmentId, this.agentId, "offline");
  }

  private scheduleNextPoll(): void {
    if (!this.running) return;
    this.pollTimer = setTimeout(async () => {
      try {
        await this.pollOnce();
      } finally {
        this.scheduleNextPoll();
      }
    }, this.pollIntervalMs);
  }

  public async pollOnce(): Promise<boolean> {
    if (!this.running || this.busy) {
      return false;
    }

    // 1. Task Discovery: search open tasks matching capabilities
    const tasksRes = await this.blackboard.tasks.listByAssessment(this.assessmentId, {
      status: "open",
    });
    if (!tasksRes.ok || tasksRes.value.length === 0) {
      return false;
    }

    const eligible = this.filterAndSortTasks(tasksRes.value);
    if (eligible.length === 0) {
      return false;
    }

    // 2. Attempt atomic claim in priority order
    for (const candidate of eligible) {
      const claimed = await this.attemptClaimTask(candidate);
      if (claimed) {
        return true;
      }
    }

    return false;
  }

  private filterAndSortTasks(tasks: ReadonlyArray<TaskRecord>): TaskRecord[] {
    const matching = tasks.filter((t) => {
      if (t.status !== "open") return false;
      return this.capabilities.includes(t.task_type);
    });

    return matching.sort((a, b) => {
      const pDiff = (PRIORITY_WEIGHTS[b.priority] ?? 0) - (PRIORITY_WEIGHTS[a.priority] ?? 0);
      if (pDiff !== 0) return pDiff;

      const smokeDiff = (b.smoke_score ?? 1) - (a.smoke_score ?? 1);
      if (smokeDiff !== 0) return smokeDiff;

      return a.created_at - b.created_at;
    });
  }

  private async attemptClaimTask(candidate: TaskRecord): Promise<boolean> {
    const now = Date.now();
    const claim: TaskClaim = {
      agent_id: this.agentId,
      host_id: this.hostId,
      pid: this.pid,
      process_start_time: this.processStartTime,
      rea_run_id: this.reaRunId,
      claimed_at: now,
      lease_until: now + this.leaseDurationMs,
    };

    const claimRes = await this.blackboard.tasks.claimTask(
      this.assessmentId,
      candidate.id,
      claim,
      candidate.cas_version,
    );

    if (!claimRes.ok) {
      // Another worker claimed it first or task blocked by dependency
      return false;
    }

    const claimedTask = claimRes.value;
    this.busy = true;

    // Execute asynchronously to not block event loop
    void this.executeClaimedTask(claimedTask);
    return true;
  }

  private async executeClaimedTask(claimedTask: TaskRecord): Promise<void> {
    const abortCtrl = new AbortController();
    this.currentAbortController = abortCtrl;
    let heartbeatTimer: NodeJS.Timeout | null = null;

    try {
      await this.blackboard.agents.updateStatus(this.assessmentId, this.agentId, "busy");

      // Start periodic lease renewal and heartbeat loop
      heartbeatTimer = setInterval(async () => {
        if (!this.busy) return;
        await this.blackboard.agents.heartbeat(this.assessmentId, this.agentId);

        const renewRes = await this.blackboard.tasks.renewLease(
          this.assessmentId,
          claimedTask.id,
          this.agentId,
          claimedTask.fencing_token,
          this.leaseDurationMs,
          this.maxTaskCeilingRenewals,
        );

        if (!renewRes.ok) {
          // Lease renewal failed (e.g. stale worker or ceiling reached)
          abortCtrl.abort();
        }
      }, this.heartbeatIntervalMs);

      // Context Projection Retrieval
      const projRes = await this.contextProjector.projectTaskContext(
        this.assessmentId,
        claimedTask.id,
      );
      if (!projRes.ok) {
        throw new Error(`Failed to project task context: ${projRes.error.message}`);
      }

      // Execute task handler with timeout and propagate abort to subprocess tree
      const result = await this.runHandlerWithTimeout(claimedTask, projRes.value, abortCtrl);

      // Submit task result with active fencing token
      await this.blackboard.tasks.completeTask(
        this.assessmentId,
        claimedTask.id,
        claimedTask.fencing_token,
        result,
      );
    } catch (error: any) {
      await this.handleTaskFailure(claimedTask, error);
    } finally {
      if (heartbeatTimer) {
        clearInterval(heartbeatTimer);
      }
      this.currentAbortController = null;
      this.busy = false;

      if (this.running) {
        await this.blackboard.agents.updateStatus(this.assessmentId, this.agentId, "idle");
      }
    }
  }

  private async runHandlerWithTimeout(
    task: TaskRecord,
    context: any,
    abortCtrl: AbortController,
  ): Promise<unknown> {
    const signal = abortCtrl.signal;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        // Propagate cancellation through signal to terminate any subprocess tree
        const timeoutErr = new Error(`Task ${task.id} execution exceeded timeout of ${this.taskTimeoutMs}ms`);
        abortCtrl.abort(timeoutErr);
        reject(timeoutErr);
      }, this.taskTimeoutMs);

      const abortHandler = () => {
        clearTimeout(timer);
        reject(new Error(`Task ${task.id} execution aborted`));
      };

      if (signal.aborted) {
        clearTimeout(timer);
        return reject(new Error(`Task ${task.id} execution already aborted`));
      }
      signal.addEventListener("abort", abortHandler, { once: true });

      this.taskHandler(task, context, signal)
        .then((res) => {
          clearTimeout(timer);
          signal.removeEventListener("abort", abortHandler);
          resolve(res);
        })
        .catch((err) => {
          clearTimeout(timer);
          signal.removeEventListener("abort", abortHandler);
          reject(err);
        });
    });
  }

  private async handleTaskFailure(task: TaskRecord, error: unknown): Promise<void> {
    const errorMsg = error instanceof Error ? error.message : String(error);

    // Apply bounded retries with exponential tracking and dead-letter queueing upon exhaustion
    await this.blackboard.tasks.retryTask(
      this.assessmentId,
      task.id,
      errorMsg,
      this.maxRetries,
    );
  }
}
