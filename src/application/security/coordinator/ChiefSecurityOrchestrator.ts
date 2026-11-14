import { ok, err, type Result } from "../../../domain/result.js";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type {
  ICentralBlackboard,
  TaskRecord,
  ObservationRecord,
} from "../../../domain/security/blackboard/types.js";
import type { BlackboardError } from "../../../domain/security/blackboard/errors.js";
import type { AgentWorker } from "./AgentWorker.js";
import type {
  OrchestratorConfig,
  ObservabilitySnapshot,
  AgentHealthInfo,
} from "./coordinatorTypes.js";

const DEFAULT_MAX_CONCURRENCY = 4;
const ABSOLUTE_MAX_CONCURRENCY = 16;

export class ChiefSecurityOrchestrator {
  private readonly blackboard: ICentralBlackboard;
  private readonly maxConcurrency: number;
  private readonly defaultMaxRetries: number;
  private readonly reapIntervalMs: number;

  private readonly workers: Map<string, AgentWorker> = new Map();
  private reaperTimer: NodeJS.Timeout | null = null;
  private running = false;
  private totalReapedLeases = 0;

  constructor(blackboard: ICentralBlackboard, config?: OrchestratorConfig) {
    this.blackboard = blackboard;
    const requestedConcurrency = config?.maxConcurrency ?? DEFAULT_MAX_CONCURRENCY;
    this.maxConcurrency = Math.min(Math.max(1, requestedConcurrency), ABSOLUTE_MAX_CONCURRENCY);
    this.defaultMaxRetries = config?.defaultMaxRetries ?? 3;
    this.reapIntervalMs = config?.reapIntervalMs ?? 500;
  }

  public getWorkerCount(): number {
    return this.workers.size;
  }

  public registerWorker(worker: AgentWorker): Result<void, BlackboardError> {
    if (this.workers.size >= this.maxConcurrency) {
      return err({
        code: "MAX_CONCURRENCY_EXCEEDED",
        maxConcurrency: this.maxConcurrency,
        currentWorkers: this.workers.size,
        message: `Cannot register agent ${worker.agentId}: concurrency ceiling of ${this.maxConcurrency} reached`,
      });
    }

    this.workers.set(worker.agentId, worker);
    return ok(undefined);
  }

  public async start(assessmentId: AssessmentId): Promise<Result<void, BlackboardError>> {
    this.running = true;

    // Start all registered workers
    for (const worker of this.workers.values()) {
      const startRes = await worker.start();
      if (!startRes.ok) {
        await this.shutdown();
        return startRes;
      }
    }

    // Start background lease reaper
    this.scheduleReaper(assessmentId);
    return ok(undefined);
  }

  public async shutdown(): Promise<void> {
    this.running = false;
    if (this.reaperTimer) {
      clearTimeout(this.reaperTimer);
      this.reaperTimer = null;
    }

    for (const worker of this.workers.values()) {
      await worker.stop();
    }
    this.workers.clear();
  }

  private scheduleReaper(assessmentId: AssessmentId): void {
    if (!this.running) return;
    this.reaperTimer = setTimeout(async () => {
      try {
        await this.reapStaleWorkers(assessmentId);
      } finally {
        this.scheduleReaper(assessmentId);
      }
    }, this.reapIntervalMs);
  }

  public async reapStaleWorkers(assessmentId: AssessmentId): Promise<number> {
    const now = Date.now();
    const res = await this.blackboard.tasks.reapExpiredLeases(assessmentId, now);
    if (res.ok && res.value > 0) {
      this.totalReapedLeases += res.value;
      return res.value;
    }
    return 0;
  }

  public async submitTask(task: TaskRecord): Promise<Result<TaskRecord, BlackboardError>> {
    return this.blackboard.tasks.create(task);
  }

  public async publishObservation(
    observation: Omit<ObservationRecord, "id" | "is_conflict">,
  ): Promise<Result<ObservationRecord, BlackboardError>> {
    return this.blackboard.observations.record(observation);
  }

  public async getObservabilitySnapshot(
    assessmentId: AssessmentId,
  ): Promise<Result<ObservabilitySnapshot, BlackboardError>> {
    try {
      const tasksRes = await this.blackboard.tasks.listByAssessment(assessmentId);
      if (!tasksRes.ok) return tasksRes;
      const tasks = tasksRes.value;

      const agentsRes = await this.blackboard.agents.listActive(assessmentId, 3600_000);
      if (!agentsRes.ok) return agentsRes;
      const agents = agentsRes.value;

      let pending = 0;
      let running = 0;
      let completed = 0;
      let failed = 0;
      let deadLetter = 0;

      for (const t of tasks) {
        if (t.status === "open" || t.status === "blocked") pending++;
        else if (t.status === "claimed" || t.status === "in_progress") running++;
        else if (t.status === "completed") completed++;
        else if (t.status === "failed") {
          failed++;
          if (t.metadata.dead_letter) deadLetter++;
        }
      }

      const activeWorkersCount = Array.from(this.workers.values()).filter((w) => w.isBusy()).length;

      const healthList: AgentHealthInfo[] = agents.map((a) => ({
        agent_id: a.agent_id,
        status: a.status,
        heartbeat_at: a.heartbeat_at,
        pid: a.pid,
        host_id: a.host_id,
      }));

      return ok({
        assessment_id: assessmentId,
        registered_agents: agents.length,
        active_workers: activeWorkersCount,
        pending_tasks: pending,
        running_tasks: running,
        completed_tasks: completed,
        failed_tasks: failed,
        dead_letter_tasks: deadLetter,
        expired_leases_reaped: this.totalReapedLeases,
        agent_health: healthList,
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "ChiefSecurityOrchestrator.getObservabilitySnapshot",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }
}

