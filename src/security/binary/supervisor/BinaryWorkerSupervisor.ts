/* eslint-disable max-lines-per-function */
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { z } from "zod";
import { err, ok, type Result } from "../../../domain/result.js";
import {
  BINARY_IPC_CONTROL_FRAME_MAX_BYTES,
  BINARY_IPC_DATA_FRAME_MAX_BYTES,
  BINARY_WORKER_PROTOCOL_VERSION,
  type BinaryWorkerAnalyzeRequest,
  type BinaryWorkerAnalyzeResponse,
  type BinaryWorkerCancelRequest,
  type BinaryWorkerHeartbeat,
  type BinaryWorkerIpcMessage,
  type BinaryWorkerReady,
  type BinaryWorkerShutdownRequest,
  validateResponseContext,
} from "../ipc/binaryWorkerProtocol.js";
import { BinaryMessageFramer } from "../ipc/binaryMessageFramer.js";
import {
  systemWindowsNativeAuthority,
  type WindowsNativeAuthority,
} from "../../../windows/WindowsNativeLoader.js";
import { WindowsOwnedProcess } from "../../../windows/WindowsOwnedProcess.js";

// ============================================================================
// Types & Interfaces
// ============================================================================

export type SupervisorState =
  | "STOPPED"
  | "STARTING"
  | "READY"
  | "BUSY"
  | "RECOVERING"
  | "SHUTTING_DOWN"
  | "TERMINATED";

export type BinarySupervisorLifecycleEvent =
  | { readonly type: "spawned"; readonly pid?: number | undefined; readonly runId: string }
  | {
      readonly type: "ready";
      readonly workerId: string;
      readonly pid: number;
      readonly supportedArchitectures: readonly string[];
    }
  | {
      readonly type: "task_dispatched";
      readonly taskId: string;
      readonly requestId: string;
      readonly fencingToken: number;
    }
  | {
      readonly type: "task_completed";
      readonly taskId: string;
      readonly requestId: string;
      readonly durationMs: number;
    }
  | {
      readonly type: "task_failed";
      readonly taskId: string;
      readonly requestId: string;
      readonly code: string;
      readonly message: string;
    }
  | {
      readonly type: "task_cancelled";
      readonly taskId: string;
      readonly requestId: string;
      readonly reason: string;
    }
  | {
      readonly type: "task_timed_out";
      readonly taskId: string;
      readonly requestId: string;
      readonly elapsedMs: number;
    }
  | { readonly type: "heartbeat_sent"; readonly messageId: string }
  | { readonly type: "heartbeat_ack"; readonly workerId: string; readonly timestamp: number }
  | { readonly type: "heartbeat_missed"; readonly missedCount: number }
  | { readonly type: "worker_unresponsive"; readonly reason: string }
  | { readonly type: "worker_killed"; readonly pid?: number | undefined; readonly signal?: string | undefined }
  | {
      readonly type: "worker_crashed";
      readonly pid?: number | undefined;
      readonly code: number | null;
      readonly signal: string | null;
    }
  | { readonly type: "worker_shutdown"; readonly pid?: number | undefined }
  | { readonly type: "worker_restarted"; readonly attempt: number }
  | {
      readonly type: "stale_response_dropped";
      readonly taskId: string;
      readonly fencingToken: number;
      readonly reason: string;
    }
  | { readonly type: "protocol_error"; readonly message: string };

export const supervisorOptionsSchema = z.strictObject({
  workerId: z.string().regex(/^wkr_[a-zA-Z0-9_-]+$/).optional(),
  allowedRoot: z.string().optional(),
  command: z.string().optional(),
  arguments: z.array(z.string()).optional(),
  cwd: z.string().optional(),
  env: z.record(z.string(), z.string().optional()).optional(),
  maxOldSpaceSizeMb: z.number().int().positive().max(65_536).default(512),
  memoryLimitBytes: z.number().int().positive().optional(),
  startupTimeoutMs: z.number().int().positive().default(10_000),
  defaultTaskTimeoutMs: z.number().int().positive().default(30_000),
  cancelGraceMs: z.number().int().positive().default(1_000),
  heartbeatIntervalMs: z.number().int().nonnegative().default(5_000),
  heartbeatTimeoutMs: z.number().int().positive().default(3_000),
  maxHeartbeatMisses: z.number().int().positive().default(2),
  autoRestart: z.boolean().default(false),
  maxRestarts: z.number().int().nonnegative().default(3),
  onEvent: z.custom<((event: BinarySupervisorLifecycleEvent) => void)>().optional(),
  windowsAuthority: z.custom<WindowsNativeAuthority>().optional(),
});

export type BinaryWorkerSupervisorConfig = z.infer<typeof supervisorOptionsSchema>;

export interface BinaryWorkerSupervisorOptions {
  readonly workerId?: string | undefined;
  readonly allowedRoot?: string | undefined;
  readonly command?: string | undefined;
  readonly arguments?: readonly string[] | undefined;
  readonly cwd?: string | undefined;
  readonly env?: NodeJS.ProcessEnv | undefined;
  readonly maxOldSpaceSizeMb?: number | undefined;
  readonly memoryLimitBytes?: number | undefined;
  readonly startupTimeoutMs?: number | undefined;
  readonly defaultTaskTimeoutMs?: number | undefined;
  readonly cancelGraceMs?: number | undefined;
  readonly heartbeatIntervalMs?: number | undefined;
  readonly heartbeatTimeoutMs?: number | undefined;
  readonly maxHeartbeatMisses?: number | undefined;
  readonly autoRestart?: boolean | undefined;
  readonly maxRestarts?: number | undefined;
  readonly onEvent?: ((event: BinarySupervisorLifecycleEvent) => void) | undefined;
  /** Testing authority hook for native Windows Job Object injection */
  readonly windowsAuthority?: WindowsNativeAuthority | undefined;
}

export interface BinarySupervisorTaskError {
  readonly code:
    | "WORKER_NOT_READY"
    | "WORKER_BUSY"
    | "WORKER_CRASHED"
    | "WORKER_UNRESPONSIVE"
    | "TIMEOUT"
    | "CANCELLED"
    | "PROTOCOL_ERROR"
    | "OVERSIZED_RESPONSE"
    | "INTERNAL_ERROR";
  readonly message: string;
  readonly details?: unknown;
}

interface ActiveTask {
  readonly request: BinaryWorkerAnalyzeRequest;
  readonly startedAt: number;
  readonly deadlineTimer: NodeJS.Timeout;
  cancelGraceTimer?: NodeJS.Timeout | undefined;
  isCancelling: boolean;
  readonly resolve: (res: Result<BinaryWorkerAnalyzeResponse, BinarySupervisorTaskError>) => void;
  readonly reject: (reason: unknown) => void;
}

// ============================================================================
// Default Script Resolver
// ============================================================================

function resolveWorkerScriptPath(): string {
  const currentDir = fileURLToPath(new URL(".", import.meta.url));
  const tsPath = resolve(currentDir, "../../../composition/binaryAnalysisWorkerProcess.ts");
  if (existsSync(tsPath)) {
    return tsPath;
  }
  const jsPath = resolve(currentDir, "../../../composition/binaryAnalysisWorkerProcess.js");
  if (existsSync(jsPath)) {
    return jsPath;
  }
  return tsPath;
}

// ============================================================================
// BinaryWorkerSupervisor Implementation
// ============================================================================

/**
 * Host-Side Process Supervisor and Lifecycle Manager for Binary Analysis Workers.
 *
 * Security Invariants & Responsibilities:
 * 1. Process Lifecycle: Spawns and supervises untrusted binary workers with isolated
 *    stdio channels and platform process tree isolation.
 * 2. Resource Enclosure: Enforces V8 heap ceilings (--max-old-space-size) and
 *    OS commit bounds via Windows Job Objects where available.
 * 3. Preemptive Watchdog: Maintains an independent host-side deadline timer.
 *    Non-yielding CPU loops (which block child IPC reads) escalate to forceful
 *    OS-level termination (kill/terminate) after a bounded cancellation grace period.
 * 4. Stale Task Defense (CAS / Fencing Token): Discriminate responses against
 *    active taskId and fencingToken. Outdated responses from previously cancelled
 *    or timed-out tasks are discarded without corrupting caller state.
 * 5. Health Monitoring: Periodic HEARTBEAT pings detect dead/unresponsive workers.
 * 6. Clean Process Tree: Ensures zero orphan child processes remain on exit, crash, or timeout.
 */
export class BinaryWorkerSupervisor {
  public readonly workerId: string;
  public readonly runId: string;
  public readonly config: BinaryWorkerSupervisorConfig;

  private state: SupervisorState = "STOPPED";
  private childProcess: ChildProcess | WindowsOwnedProcess | null = null;
  private childPid: number | undefined;
  private readonly framer = new BinaryMessageFramer();
  private readonly onEvent?: ((event: BinarySupervisorLifecycleEvent) => void) | undefined;
  private readonly windowsAuthority?: WindowsNativeAuthority | undefined;

  private activeTask: ActiveTask | null = null;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private consecutiveMissedHeartbeats = 0;
  private pendingHeartbeats = new Set<string>();
  private workerInstanceId = randomUUID();
  private restartCount = 0;

  private readyWaiters: Array<{
    resolve: (ready: BinaryWorkerReady) => void;
    reject: (err: Error) => void;
    timer: NodeJS.Timeout;
  }> = [];

  private shutdownWaiters: Array<{
    resolve: () => void;
    reject: (err: Error) => void;
  }> = [];

  constructor(options?: BinaryWorkerSupervisorOptions) {
    // Strict options parsing
    const parsed = supervisorOptionsSchema.safeParse(options ?? {});
    if (!parsed.success) {
      throw new Error(`Invalid supervisor configuration: ${parsed.error.message}`);
    }
    this.config = parsed.data;

    this.workerId = this.config.workerId ?? `wkr_${randomUUID().replace(/-/g, "")}`;
    this.runId = `run_sup_${randomUUID().replace(/-/g, "")}`;
    this.onEvent = options?.onEvent;
    this.windowsAuthority = options?.windowsAuthority;
  }

  public getState(): SupervisorState {
    return this.state;
  }

  public getChildPid(): number | undefined {
    return this.childPid;
  }

  public getRestartCount(): number {
    return this.restartCount;
  }

  public getWorkerInstanceId(): string {
    return this.workerInstanceId;
  }

  /**
   * Spawns the child worker process and performs the startup handshake.
   */
  public async start(): Promise<BinaryWorkerReady> {
    if (this.state === "READY" || this.state === "BUSY") {
      throw new Error(`Supervisor is already active in state '${this.state}'`);
    }

    this.state = "STARTING";
    return this.spawnAndHandshake();
  }

  private async spawnAndHandshake(): Promise<BinaryWorkerReady> {
    this.workerInstanceId = randomUUID();
    this.framer.reset();
    this.pendingHeartbeats.clear();
    this.consecutiveMissedHeartbeats = 0;

    const scriptPath = resolveWorkerScriptPath();
    const command = this.config.command ?? process.execPath;
    let spawnArgs: string[];

    if (this.config.arguments !== undefined) {
      spawnArgs = [...this.config.arguments];
    } else {
      const nodeArgs: string[] = [`--max-old-space-size=${this.config.maxOldSpaceSizeMb}`];
      if (scriptPath.endsWith(".ts")) {
        nodeArgs.push("--import", "tsx");
      }
      nodeArgs.push(scriptPath);
      spawnArgs = nodeArgs;
    }

    const env: NodeJS.ProcessEnv = {
      ...process.env,
      ...this.config.env,
      REA_BINARY_WORKER_ID: this.workerId,
      REA_BINARY_ALLOWED_ROOT: this.config.allowedRoot ?? "",
      REA_PROCESS_RUN_ID: this.runId,
    };

    // Determine whether to use native WindowsOwnedProcess
    const isWin = process.platform === "win32";
    const nativeAuth = this.windowsAuthority ?? (isWin ? systemWindowsNativeAuthority() : null);
    const hasNativeWin = nativeAuth !== null && ("available" in nativeAuth ? nativeAuth.available : Boolean(nativeAuth));

    if (this.config.memoryLimitBytes !== undefined && (!isWin || !hasNativeWin)) {
      throw new Error(
        "Owned process memory limits require the Windows Job Object launcher with available native authority; no limit can be enforced on this host.",
      );
    }

    if (isWin && hasNativeWin) {
      const authority = this.windowsAuthority ?? (nativeAuth as { available: true; authority: WindowsNativeAuthority }).authority;
      const winProc = new WindowsOwnedProcess(
        command,
        spawnArgs,
        this.config.cwd,
        env,
        false,
        {
          protocolStdin: true,
          ...(this.config.memoryLimitBytes === undefined ? {} : { memoryLimitBytes: this.config.memoryLimitBytes }),
          authority,
        },
      );
      this.childProcess = winProc;
      this.childPid = winProc.pid;
      this.setupWindowsProcessListeners(winProc);
    } else {
      const child = spawn(command, spawnArgs, {
        cwd: this.config.cwd,
        env,
        stdio: ["pipe", "pipe", "pipe"],
        detached: !isWin,
      });

      this.childProcess = child;
      this.childPid = child.pid;
      this.setupNodeChildListeners(child);
    }

    this.emitEvent({ type: "spawned", pid: this.childPid, runId: this.runId });

    return new Promise<BinaryWorkerReady>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.emitEvent({
          type: "protocol_error",
          message: `Startup timeout after ${this.config.startupTimeoutMs}ms waiting for WORKER_READY`,
        });
        this.forceKillProcess();
        this.state = "TERMINATED";
        reject(new Error(`Worker startup timed out after ${this.config.startupTimeoutMs}ms`));
      }, this.config.startupTimeoutMs);

      this.readyWaiters.push({ resolve, reject, timer });
    });
  }

  private setupNodeChildListeners(child: ChildProcess): void {
    child.stdin?.on("error", () => {
      // Ignore EPIPE or write errors after child termination
    });

    child.stdout?.on("data", (chunk: Buffer) => {
      this.handleStdoutChunk(chunk);
    });

    child.stderr?.on("data", (_chunk: Buffer) => {
      // Diagnostic output from worker
    });

    child.on("error", (err: Error) => {
      this.handleProcessError(err);
    });

    child.on("exit", (code: number | null, signal: NodeJS.Signals | null) => {
      this.handleProcessExit(code, signal);
    });
  }

  private setupWindowsProcessListeners(winProc: WindowsOwnedProcess): void {
    winProc.stdin?.on("error", () => {
      // Ignore EPIPE or write errors
    });

    winProc.stdout.on("data", (chunk: Buffer) => {
      this.handleStdoutChunk(chunk);
    });

    winProc.stderr.on("data", (_chunk: Buffer) => {
      // Diagnostic output
    });

    winProc.on("exit", (code: number | null) => {
      this.handleProcessExit(code, null);
    });

    winProc.on("error", (err: Error) => {
      this.handleProcessError(err);
    });
  }

  private handleStdoutChunk(chunk: Buffer): void {
    const results = this.framer.push(chunk);
    for (const res of results) {
      if (res.ok) {
        this.handleIncomingMessage(res.value);
      } else {
        const errorMsg = `Protocol framing error from worker: ${res.error.message}`;
        this.emitEvent({ type: "protocol_error", message: errorMsg });

        if (this.activeTask) {
          const task = this.activeTask;
          this.clearTaskTimers(task);
          this.activeTask = null;
          task.resolve(
            err({
              code:
                res.error.code === "FRAME_OVERSIZED" || res.error.code === "CONTROL_FRAME_OVERSIZED"
                  ? "OVERSIZED_RESPONSE"
                  : "PROTOCOL_ERROR",
              message: errorMsg,
            }),
          );
        }

        // Fatal framing error from untrusted child -> terminate process
        this.forceKillProcess();
        this.state = "TERMINATED";
      }
    }
  }

  private handleIncomingMessage(msg: BinaryWorkerIpcMessage): void {
    switch (msg.kind) {
      case "WORKER_READY": {
        this.handleWorkerReady(msg);
        break;
      }
      case "HEARTBEAT": {
        this.handleHeartbeatAck(msg);
        break;
      }
      case "ANALYZE_RESPONSE": {
        this.handleAnalyzeResponse(msg);
        break;
      }
      case "CANCEL_ACK": {
        this.handleCancelAck(msg);
        break;
      }
      case "SHUTDOWN_ACK": {
        this.handleShutdownAck();
        break;
      }
      case "WORKER_ERROR": {
        this.handleWorkerError(msg);
        break;
      }
      default: {
        this.emitEvent({
          type: "protocol_error",
          message: `Unexpected message kind: ${(msg as { kind: string }).kind}`,
        });
      }
    }
  }

  private handleWorkerReady(ready: BinaryWorkerReady): void {
    if (this.readyWaiters.length > 0) {
      const waiter = this.readyWaiters.shift()!;
      clearTimeout(waiter.timer);
      this.state = "READY";
      this.emitEvent({
        type: "ready",
        workerId: ready.workerId,
        pid: ready.pid,
        supportedArchitectures: ready.supportedArchitectures,
      });
      this.startHeartbeatLoop();
      waiter.resolve(ready);
    }
  }

  private handleHeartbeatAck(heartbeat: BinaryWorkerHeartbeat): void {
    this.pendingHeartbeats.delete(heartbeat.messageId);
    this.consecutiveMissedHeartbeats = 0;
    this.emitEvent({
      type: "heartbeat_ack",
      workerId: heartbeat.workerId,
      timestamp: heartbeat.timestamp,
    });
  }

  private handleAnalyzeResponse(response: BinaryWorkerAnalyzeResponse): void {
    if (!this.activeTask) {
      this.emitEvent({
        type: "stale_response_dropped",
        taskId: response.taskId,
        fencingToken: response.fencingToken,
        reason: "No active task in supervisor",
      });
      return;
    }

    const task = this.activeTask;

    // Fencing token and task correlation defense (CAS validation)
    if (response.taskId !== task.request.taskId || response.fencingToken !== task.request.fencingToken) {
      this.emitEvent({
        type: "stale_response_dropped",
        taskId: response.taskId,
        fencingToken: response.fencingToken,
        reason: `Mismatched correlation: expected task=${task.request.taskId} fencingToken=${task.request.fencingToken}, got task=${response.taskId} fencingToken=${response.fencingToken}`,
      });
      return;
    }

    // Context validation
    const contextValidation = validateResponseContext(
      {
        assessmentId: task.request.assessmentId,
        assetId: task.request.assetId,
        binarySha256: task.request.binarySha256,
        runId: task.request.runId,
        taskId: task.request.taskId,
        fencingToken: task.request.fencingToken,
        workerId: task.request.workerId,
      },
      response,
    );

    this.clearTaskTimers(task);
    this.activeTask = null;
    this.state = "READY";

    if (!contextValidation.ok) {
      this.emitEvent({
        type: "task_failed",
        taskId: task.request.taskId,
        requestId: task.request.messageId,
        code: contextValidation.error.code,
        message: contextValidation.error.message,
      });
      task.resolve(
        err({
          code: "PROTOCOL_ERROR",
          message: `Context validation failure: ${contextValidation.error.message}`,
        }),
      );
      return;
    }

    const durationMs = Date.now() - task.startedAt;
    this.emitEvent({
      type: "task_completed",
      taskId: task.request.taskId,
      requestId: task.request.messageId,
      durationMs,
    });
    task.resolve(ok(response));
  }

  private handleCancelAck(msg: Extract<BinaryWorkerIpcMessage, { kind: "CANCEL_ACK" }>): void {
    if (this.activeTask && this.activeTask.request.taskId === msg.taskId) {
      const task = this.activeTask;
      this.clearTaskTimers(task);
      this.activeTask = null;
      this.state = "READY";
      this.emitEvent({
        type: "task_cancelled",
        taskId: task.request.taskId,
        requestId: task.request.messageId,
        reason: "Cancelled by parent",
      });
      task.resolve(
        err({
          code: "CANCELLED",
          message: `Task ${msg.taskId} cancellation acknowledged by worker`,
        }),
      );
    }
  }

  private handleShutdownAck(): void {
    if (this.shutdownWaiters.length > 0) {
      const waiter = this.shutdownWaiters.shift()!;
      waiter.resolve();
    }
  }

  private handleWorkerError(msg: Extract<BinaryWorkerIpcMessage, { kind: "WORKER_ERROR" }>): void {
    this.emitEvent({
      type: "protocol_error",
      message: `Worker error [${msg.code}]: ${msg.message}`,
    });

    if (this.activeTask && (!msg.inReplyTo || msg.inReplyTo === this.activeTask.request.messageId)) {
      const task = this.activeTask;
      this.clearTaskTimers(task);
      this.activeTask = null;
      this.state = "READY";
      task.resolve(
        err({
          code: msg.code === "TIMEOUT" ? "TIMEOUT" : "INTERNAL_ERROR",
          message: msg.message,
        }),
      );
    }

    if (!msg.recoverable) {
      this.forceKillProcess();
      this.state = "TERMINATED";
    }
  }

  private handleProcessError(err: Error): void {
    this.emitEvent({ type: "protocol_error", message: `Process error: ${err.message}` });
    if (this.readyWaiters.length > 0) {
      const waiter = this.readyWaiters.shift()!;
      clearTimeout(waiter.timer);
      waiter.reject(err);
    }
  }

  private handleProcessExit(code: number | null, signal: string | null): void {
    this.stopHeartbeatLoop();
    this.emitEvent({
      type: "worker_crashed",
      pid: this.childPid,
      code,
      signal,
    });

    // Settle pending startup waiters
    if (this.readyWaiters.length > 0) {
      const waiter = this.readyWaiters.shift()!;
      clearTimeout(waiter.timer);
      waiter.reject(new Error(`Worker exited with code ${code ?? "null"} / signal ${signal ?? "null"} before readiness`));
    }

    // Settle pending active task
    if (this.activeTask) {
      const task = this.activeTask;
      this.clearTaskTimers(task);
      this.activeTask = null;
      task.resolve(
        err({
          code: "WORKER_CRASHED",
          message: `Worker process exited unexpectedly (code: ${code ?? "null"}, signal: ${signal ?? "null"}) during task execution`,
          details: { code, signal },
        }),
      );
    }

    // Settle shutdown waiters
    while (this.shutdownWaiters.length > 0) {
      const waiter = this.shutdownWaiters.shift()!;
      waiter.resolve();
    }

    this.childProcess = null;
    this.childPid = undefined;

    if (this.state !== "SHUTTING_DOWN" && this.state !== "STOPPED") {
      this.state = "TERMINATED";

      if (this.config.autoRestart && this.restartCount < this.config.maxRestarts) {
        this.restartCount++;
        this.state = "RECOVERING";
        this.emitEvent({ type: "worker_restarted", attempt: this.restartCount });
        this.spawnAndHandshake().catch((cause) => {
          this.emitEvent({
            type: "protocol_error",
            message: `Auto-restart failed: ${cause instanceof Error ? cause.message : String(cause)}`,
          });
          this.state = "TERMINATED";
        });
      }
    }
  }

  // ============================================================================
  // Task Execution & Watchdog Timers
  // ============================================================================

  /**
   * Dispatches a binary analysis task to the worker and monitors its execution.
   */
  public async executeTask(
    request: BinaryWorkerAnalyzeRequest,
  ): Promise<Result<BinaryWorkerAnalyzeResponse, BinarySupervisorTaskError>> {
    if (this.state !== "READY") {
      return err({
        code: this.state === "BUSY" ? "WORKER_BUSY" : "WORKER_NOT_READY",
        message: `Supervisor cannot accept tasks in state '${this.state}'`,
      });
    }

    const stdin = this.getStdinStream();
    if (!stdin) {
      return err({
        code: "INTERNAL_ERROR",
        message: "Worker process has no writable stdin stream",
      });
    }

    const now = Date.now();
    const deadlineMs = request.deadline > now ? request.deadline - now : this.config.defaultTaskTimeoutMs;

    this.state = "BUSY";

    return new Promise<Result<BinaryWorkerAnalyzeResponse, BinarySupervisorTaskError>>((resolve, reject) => {
      const deadlineTimer = setTimeout(() => {
        this.handleTaskTimeout();
      }, deadlineMs);

      this.activeTask = {
        request,
        startedAt: now,
        deadlineTimer,
        isCancelling: false,
        resolve,
        reject,
      };

      this.emitEvent({
        type: "task_dispatched",
        taskId: request.taskId,
        requestId: request.messageId,
        fencingToken: request.fencingToken,
      });

      const frame = `${JSON.stringify(request)}\n`;
      if (Buffer.byteLength(frame) > BINARY_IPC_DATA_FRAME_MAX_BYTES) {
        this.clearTaskTimers(this.activeTask);
        this.activeTask = null;
        this.state = "READY";
        resolve(
          err({
            code: "OVERSIZED_RESPONSE",
            message: `Request frame exceeds byte budget of ${BINARY_IPC_DATA_FRAME_MAX_BYTES} bytes`,
          }),
        );
        return;
      }

      stdin.write(frame, "utf8", (error) => {
        if (error) {
          if (this.activeTask) {
            const task = this.activeTask;
            this.clearTaskTimers(task);
            this.activeTask = null;
            this.state = "READY";
            task.resolve(
              err({
                code: "INTERNAL_ERROR",
                message: `Failed to write request to worker stdin: ${error.message}`,
              }),
            );
          }
        }
      });
    });
  }

  /**
   * Host-Side Preemptive Timeout Handler.
   *
   * Dual-Tier Escalation:
   * 1. Sends a cooperative CANCEL frame over stdin.
   * 2. Sets a cancellation grace timer (cancelGraceMs).
   * 3. If worker fails to respond (e.g. CPU-bound infinite loop in instruction decoder or CFG builder),
   *    escalates immediately to forceful OS-level termination.
   */
  private handleTaskTimeout(): void {
    if (!this.activeTask) return;
    const task = this.activeTask;
    task.isCancelling = true;

    const elapsed = Date.now() - task.startedAt;
    this.emitEvent({
      type: "task_timed_out",
      taskId: task.request.taskId,
      requestId: task.request.messageId,
      elapsedMs: elapsed,
    });

    // Attempt cooperative cancellation
    const cancelMsg: BinaryWorkerCancelRequest = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "CANCEL",
      messageId: randomUUID(),
      taskId: task.request.taskId,
      reason: `Host deadline exceeded after ${elapsed}ms`,
    };

    const stdin = this.getStdinStream();
    if (stdin && !stdin.destroyed) {
      try {
        stdin.write(`${JSON.stringify(cancelMsg)}\n`, "utf8", () => {});
      } catch {
        // Stream write failure
      }
    }

    // Set grace timer for forceful OS preemption
    task.cancelGraceTimer = setTimeout(() => {
      this.escalateForcedTimeoutTermination(task, elapsed);
    }, this.config.cancelGraceMs);
  }

  private escalateForcedTimeoutTermination(task: ActiveTask, elapsedMs: number): void {
    if (this.activeTask !== task) return;

    this.emitEvent({
      type: "worker_killed",
      pid: this.childPid,
      signal: "SIGKILL",
    });

    this.forceKillProcess();
    this.clearTaskTimers(task);
    this.activeTask = null;
    this.state = "TERMINATED";

    task.resolve(
      err({
        code: "TIMEOUT",
        message: `Task ${task.request.taskId} timed out after ${elapsedMs}ms and worker was forcefully terminated (grace period exceeded)`,
      }),
    );
  }

  /**
   * Explicitly cancels an active task.
   */
  public async cancelTask(taskId: string, reason = "Explicit cancellation by parent"): Promise<boolean> {
    if (!this.activeTask || this.activeTask.request.taskId !== taskId) {
      return false;
    }

    const task = this.activeTask;
    task.isCancelling = true;

    const cancelMsg: BinaryWorkerCancelRequest = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "CANCEL",
      messageId: randomUUID(),
      taskId,
      reason,
    };

    const stdin = this.getStdinStream();
    if (stdin && !stdin.destroyed) {
      try {
        stdin.write(`${JSON.stringify(cancelMsg)}\n`, "utf8", () => {});
      } catch {
        // Stream failure
      }
    }

    task.cancelGraceTimer = setTimeout(() => {
      if (this.activeTask === task) {
        this.forceKillProcess();
        this.clearTaskTimers(task);
        this.activeTask = null;
        this.state = "TERMINATED";
        task.resolve(
          err({
            code: "CANCELLED",
            message: `Task ${taskId} cancelled and worker killed after grace period`,
          }),
        );
      }
    }, this.config.cancelGraceMs);

    return true;
  }

  // ============================================================================
  // Heartbeat & Health Monitoring
  // ============================================================================

  private startHeartbeatLoop(): void {
    if (this.config.heartbeatIntervalMs <= 0) return;
    this.stopHeartbeatLoop();

    this.heartbeatTimer = setInterval(() => {
      this.sendHeartbeatPing();
    }, this.config.heartbeatIntervalMs);
  }

  private stopHeartbeatLoop(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  private sendHeartbeatPing(): void {
    if (this.state !== "READY" && this.state !== "BUSY") return;

    if (this.pendingHeartbeats.size > 0) {
      this.consecutiveMissedHeartbeats++;
      this.emitEvent({
        type: "heartbeat_missed",
        missedCount: this.consecutiveMissedHeartbeats,
      });

      if (this.consecutiveMissedHeartbeats >= this.config.maxHeartbeatMisses) {
        this.emitEvent({
          type: "worker_unresponsive",
          reason: `Missed ${this.consecutiveMissedHeartbeats} consecutive heartbeats`,
        });
        this.forceKillProcess();
        this.state = "TERMINATED";
        return;
      }
    }

    const msgId = randomUUID();
    const heartbeat: BinaryWorkerHeartbeat = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "HEARTBEAT",
      messageId: msgId,
      workerId: this.workerId,
      timestamp: Date.now(),
      activeTaskId: this.activeTask?.request.taskId ?? null,
      fencingToken: this.activeTask?.request.fencingToken ?? null,
    };

    this.pendingHeartbeats.add(msgId);
    this.emitEvent({ type: "heartbeat_sent", messageId: msgId });

    const stdin = this.getStdinStream();
    if (stdin && !stdin.destroyed) {
      try {
        stdin.write(`${JSON.stringify(heartbeat)}\n`, "utf8", () => {});
      } catch {
        // Stream failure handled in process exit
      }
    }
  }

  // ============================================================================
  // Shutdown & Process Termination
  // ============================================================================

  /**
   * Graceful shutdown: Sends SHUTDOWN frame, awaits SHUTDOWN_ACK or child exit,
   * then escalates to forceful termination if child does not exit in time.
   */
  public async shutdown(graceMs = 1_000): Promise<void> {
    if (this.state === "STOPPED" || this.childProcess === null) {
      this.state = "STOPPED";
      return;
    }

    this.state = "SHUTTING_DOWN";
    this.stopHeartbeatLoop();

    const shutdownMsg: BinaryWorkerShutdownRequest = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "SHUTDOWN",
      messageId: randomUUID(),
      reason: "Parent supervisor initiated shutdown",
      gracePeriodMs: graceMs,
    };

    const stdin = this.getStdinStream();
    if (stdin && !stdin.destroyed) {
      try {
        stdin.write(`${JSON.stringify(shutdownMsg)}\n`, "utf8", () => {});
      } catch {
        // Ignored
      }
    }

    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        this.forceKillProcess();
        resolve();
      }, graceMs);

      this.shutdownWaiters.push({
        resolve: () => {
          clearTimeout(timer);
          this.forceKillProcess();
          resolve();
        },
        reject: () => {
          clearTimeout(timer);
          this.forceKillProcess();
          resolve();
        },
      });
    });

    this.emitEvent({ type: "worker_shutdown", pid: this.childPid });
    this.state = "STOPPED";
  }

  /**
   * Forcefully kills the worker process and all descendant processes in its process group.
   */
  public forceKillProcess(signal: NodeJS.Signals = "SIGKILL"): void {
    if (!this.childProcess) return;

    try {
      if ("cleanup" in this.childProcess && typeof this.childProcess.cleanup === "function") {
        void this.childProcess.cleanup();
      } else if ("kill" in this.childProcess && typeof this.childProcess.kill === "function") {
        if (process.platform === "win32") {
          const pid = this.childProcess.pid;
          this.childProcess.kill(signal);
          if (pid !== undefined) {
            try {
              execFile("taskkill", ["/pid", String(pid), "/T", "/F"], () => {});
            } catch {
              // Ignore taskkill errors if process already exited
            }
          }
        } else {
          // On POSIX, signal the entire process group if detached
          const pid = this.childProcess.pid;
          if (pid !== undefined) {
            try {
              process.kill(-pid, signal);
            } catch {
              this.childProcess.kill(signal);
            }
          } else {
            this.childProcess.kill(signal);
          }
        }
      }
    } catch {
      // Process already terminated or ESRCH
    }

    this.emitEvent({ type: "worker_killed", pid: this.childPid, signal });
  }

  private clearTaskTimers(task: ActiveTask): void {
    clearTimeout(task.deadlineTimer);
    if (task.cancelGraceTimer) {
      clearTimeout(task.cancelGraceTimer);
      task.cancelGraceTimer = undefined;
    }
  }

  private getStdinStream(): { write: (data: string | Buffer, encoding?: string, cb?: (err?: Error) => void) => boolean; destroyed?: boolean } | null {
    if (!this.childProcess) return null;
    return (this.childProcess as { stdin?: { write: (data: string | Buffer, encoding?: string, cb?: (err?: Error) => void) => boolean; destroyed?: boolean } }).stdin ?? null;
  }

  private emitEvent(event: BinarySupervisorLifecycleEvent): void {
    if (this.onEvent) {
      try {
        this.onEvent(event);
      } catch {
        // Observers must not break supervisor operations
      }
    }
  }
}

