import { randomUUID } from "node:crypto";
import { getHeapStatistics } from "node:v8";
import type { Readable, Writable } from "node:stream";
import { err, ok, type Result } from "../../../domain/result.js";
import {
  BINARY_WORKER_PROTOCOL_VERSION,
  type BinaryWorkerAnalyzeRequest,
  type BinaryWorkerAnalyzeResponse,
  type BinaryWorkerCancelRequest,
  type BinaryWorkerHeartbeat,
  type BinaryWorkerIpcMessage,
  type BinaryWorkerReady,
  type BinaryWorkerShutdownRequest,
  type BinaryWorkerErrorResponse,
  type RawAnalysisResultPayload,
} from "../ipc/binaryWorkerProtocol.js";
import { BinaryMessageFramer } from "../ipc/binaryMessageFramer.js";
import { BinaryInputResolver } from "./BinaryInputResolver.js";
import {
  type BinaryAnalysisStageDispatcher,
  DefaultBinaryAnalysisDispatcher,
} from "./BinaryAnalysisDispatcher.js";

export type WorkerState =
  | "UNINITIALIZED"
  | "READY"
  | "PROCESSING"
  | "SHUTTING_DOWN"
  | "TERMINATED";

export interface BinaryWorkerRuntimeOptions {
  readonly workerId?: string | undefined;
  readonly allowedRoot?: string | undefined;
  readonly inputStream?: Readable | undefined;
  readonly outputStream?: Writable | undefined;
  readonly diagnosticStream?: Writable | undefined;
  readonly dispatcher?: BinaryAnalysisStageDispatcher | undefined;
}

/**
 * Strips host filesystem paths, internal stack traces, and sensitive data from error messages.
 */
export function sanitizeErrorMessage(rawMessage: string): string {
  let cleaned = rawMessage.split("\n")[0] ?? "Unknown error";
  // Redact Windows absolute paths
  cleaned = cleaned.replace(/[A-Za-z]:\\[^:\s]+/g, "<redacted_path>");
  // Redact Unix absolute paths
  cleaned = cleaned.replace(/\/(?:[a-zA-Z0-9_.-]+\/)+[a-zA-Z0-9_.-]+/g, "<redacted_path>");
  return cleaned.slice(0, 512);
}

/**
 * Isolated Child Process Runtime for Binary Analysis.
 *
 * Security Invariants:
 * 1. Has ZERO SQLite connections, repositories, or blackboard persistence access.
 * 2. Has ZERO HMAC keys, keyring access, or evidence signing authority.
 * 3. Never awards vulnerability verdicts (cannot issue finding states).
 * 4. Stdio discipline: stdout is strictly reserved for framed NDJSON protocol messages.
 *    All diagnostic logs flow strictly to stderr.
 * 5. Deterministic termination on parent disconnect (stdin EOF).
 */
export class BinaryWorkerRuntime {
  public readonly workerId: string;
  private state: WorkerState = "UNINITIALIZED";

  private readonly inputStream: Readable;
  private readonly outputStream: Writable;
  private readonly diagnosticStream: Writable;
  private readonly framer: BinaryMessageFramer;
  private readonly resolver: BinaryInputResolver;
  private readonly dispatcher: BinaryAnalysisStageDispatcher;

  private activeTaskId: string | undefined;
  private activeFencingToken: number | undefined;
  private activeAbortController: AbortController | undefined;

  private exitPromiseResolve: (() => void) | undefined;
  private isProcessingQueue = false;
  private readonly incomingQueue: BinaryWorkerIpcMessage[] = [];

  constructor(options?: BinaryWorkerRuntimeOptions) {
    const rawId = options?.workerId;
    if (rawId && /^wkr_[a-zA-Z0-9_-]+$/.test(rawId)) {
      this.workerId = rawId;
    } else {
      this.workerId = `wkr_${randomUUID().replace(/-/g, "")}`;
    }

    this.inputStream = options?.inputStream ?? process.stdin;
    this.outputStream = options?.outputStream ?? process.stdout;
    this.diagnosticStream = options?.diagnosticStream ?? process.stderr;

    this.framer = new BinaryMessageFramer();
    this.resolver = new BinaryInputResolver({ allowedRoot: options?.allowedRoot });
    this.dispatcher = options?.dispatcher ?? new DefaultBinaryAnalysisDispatcher();
  }

  public getState(): WorkerState {
    return this.state;
  }

  /**
   * Starts the worker runtime:
   * 1. Emits WORKER_READY to stdout.
   * 2. Binds listeners to stdin.
   * 3. Returns a Promise that resolves when the worker terminates (via SHUTDOWN or stdin EOF).
   */
  public async start(): Promise<void> {
    if (this.state !== "UNINITIALIZED") {
      throw new Error(`Worker already started (state: ${this.state})`);
    }

    const terminationPromise = new Promise<void>((resolve) => {
      this.exitPromiseResolve = resolve;
    });

    // 1. Send WORKER_READY handshake
    this.state = "READY";
    await this.sendReadyFrame();
    this.writeDiagnostic(`[BinaryWorkerRuntime] Worker ${this.workerId} started in pid ${process.pid}`);

    // 2. Attach stream listeners
    this.inputStream.on("data", (chunk: Buffer) => this.handleDataChunk(chunk));
    this.inputStream.on("end", () => this.handleStreamEnd());
    this.inputStream.on("error", (errCause) => {
      this.writeDiagnostic(`[BinaryWorkerRuntime] Stdin error: ${sanitizeErrorMessage(String(errCause))}`);
      this.terminate();
    });

    return terminationPromise;
  }

  /**
   * Graceful shutdown of the worker runtime.
   */
  public async shutdown(): Promise<void> {
    if (this.state === "SHUTTING_DOWN" || this.state === "TERMINATED") {
      return;
    }
    this.state = "SHUTTING_DOWN";
    this.writeDiagnostic(`[BinaryWorkerRuntime] Worker ${this.workerId} shutting down...`);

    if (this.activeAbortController) {
      this.activeAbortController.abort();
      this.activeAbortController = undefined;
    }

    this.terminate();
  }

  private terminate(): void {
    if (this.state === "TERMINATED") {
      return;
    }
    this.state = "TERMINATED";
    this.inputStream.removeAllListeners("data");
    this.inputStream.removeAllListeners("end");
    this.inputStream.removeAllListeners("error");

    if (typeof (this.inputStream as any).pause === "function") {
      (this.inputStream as any).pause();
    }
    if (typeof (this.inputStream as any).destroy === "function") {
      (this.inputStream as any).destroy();
    }

    if (this.exitPromiseResolve) {
      this.exitPromiseResolve();
      this.exitPromiseResolve = undefined;
    }
  }

  private handleDataChunk(chunk: Buffer): void {
    if (this.state === "SHUTTING_DOWN" || this.state === "TERMINATED") {
      return;
    }

    const frameResults = this.framer.push(chunk);
    for (const result of frameResults) {
      if (!result.ok) {
        this.writeDiagnostic(`[BinaryWorkerRuntime] Framing error: ${result.error.code} - ${result.error.message}`);
        void this.sendErrorFrame(
          "MALFORMED_REQUEST",
          sanitizeErrorMessage(result.error.message),
          true,
        );
        continue;
      }

      this.incomingQueue.push(result.value);
    }

    void this.drainQueue();
  }

  private handleStreamEnd(): void {
    this.writeDiagnostic("[BinaryWorkerRuntime] Stdin reached EOF (parent closed pipe); terminating");
    if (this.activeAbortController) {
      this.activeAbortController.abort();
    }
    this.terminate();
  }

  private async drainQueue(): Promise<void> {
    if (this.isProcessingQueue) {
      return;
    }
    this.isProcessingQueue = true;

    try {
      while (this.incomingQueue.length > 0 && this.state !== "TERMINATED") {
        const message = this.incomingQueue.shift();
        if (!message) break;
        await this.processMessage(message);
      }
    } finally {
      this.isProcessingQueue = false;
    }
  }

  private async processMessage(message: BinaryWorkerIpcMessage): Promise<void> {
    switch (message.kind) {
      case "ANALYZE_REQUEST":
        await this.handleAnalyzeRequest(message);
        break;

      case "HEARTBEAT":
        await this.handleHeartbeatRequest(message);
        break;

      case "CANCEL":
        await this.handleCancelRequest(message);
        break;

      case "SHUTDOWN":
        await this.handleShutdownRequest(message);
        break;

      default:
        this.writeDiagnostic(`[BinaryWorkerRuntime] Unexpected message kind: ${(message as any).kind}`);
        await this.sendErrorFrame(
          "MALFORMED_REQUEST",
          `Unexpected message kind '${(message as any).kind}' received by worker`,
          true,
          (message as any).messageId,
        );
        break;
    }
  }

  private async handleAnalyzeRequest(request: BinaryWorkerAnalyzeRequest): Promise<void> {
    // 1. Worker ID match validation
    if (request.workerId !== this.workerId) {
      this.writeDiagnostic(
        `[BinaryWorkerRuntime] Worker ID mismatch: expected ${this.workerId}, got ${request.workerId}`,
      );
      await this.sendErrorFrame(
        "MALFORMED_REQUEST",
        "Target worker ID does not match current worker runtime",
        true,
        request.messageId,
        request.taskId,
      );
      return;
    }

    // 2. Deadline check
    const now = Date.now();
    if (request.deadline <= now) {
      this.writeDiagnostic(`[BinaryWorkerRuntime] Request deadline expired before start (deadline: ${request.deadline}, now: ${now})`);
      await this.sendAnalyzeResponse(request, "FAILED", {
        isComplete: false,
        outcome: "FAILED",
        decodedBytes: 0,
        totalBytes: 0,
        haltReason: "Execution deadline expired prior to analysis commencement",
      }, {}, ["Task execution deadline was exceeded before start"]);
      return;
    }

    // 3. Set active task execution context
    this.state = "PROCESSING";
    this.activeTaskId = request.taskId;
    this.activeFencingToken = request.fencingToken;
    this.activeAbortController = new AbortController();

    const startWall = performance.now();
    const startCpu = process.cpuUsage();

    try {
      // 4. Resolve binary input
      const resolveRes = await this.resolver.resolve(request.binaryInput);
      if (!resolveRes.ok) {
        this.writeDiagnostic(`[BinaryWorkerRuntime] Input resolution failed: ${resolveRes.error.message}`);
        await this.sendAnalyzeResponse(
          request,
          "FAILED",
          {
            isComplete: false,
            outcome: "FAILED",
            decodedBytes: 0,
            totalBytes: 0,
            haltReason: resolveRes.error.message,
          },
          {},
          [resolveRes.error.message],
          this.computeResourceUsage(startCpu, startWall),
        );
        return;
      }

      // 5. Dispatch stage analysis
      const dispatchRes = await this.dispatcher.dispatch(
        request,
        resolveRes.value.buffer,
        this.activeAbortController.signal,
      );

      const resourceUsage = this.computeResourceUsage(startCpu, startWall);

      if (!dispatchRes.ok) {
        this.writeDiagnostic(`[BinaryWorkerRuntime] Dispatch error: ${dispatchRes.error.message}`);
        await this.sendAnalyzeResponse(
          request,
          "FAILED",
          {
            isComplete: false,
            outcome: "FAILED",
            decodedBytes: 0,
            totalBytes: resolveRes.value.byteSize,
            haltReason: dispatchRes.error.message,
          },
          {},
          [dispatchRes.error.message],
          resourceUsage,
        );
        return;
      }

      // 6. Return successful or partial response
      await this.sendAnalyzeResponse(
        request,
        dispatchRes.value.executionStatus,
        dispatchRes.value.decodeCompleteness,
        dispatchRes.value.resultPayload,
        dispatchRes.value.diagnostics,
        resourceUsage,
        dispatchRes.value.resultDigest,
      );
    } catch (errCause) {
      const sanitized = sanitizeErrorMessage(String(errCause));
      this.writeDiagnostic(`[BinaryWorkerRuntime] Uncaught analysis error: ${sanitized}`);
      await this.sendAnalyzeResponse(
        request,
        "FAILED",
        {
          isComplete: false,
          outcome: "FAILED",
          decodedBytes: 0,
          totalBytes: 0,
          haltReason: sanitized,
        },
        {},
        [sanitized],
        this.computeResourceUsage(startCpu, startWall),
      );
    } finally {
      this.activeTaskId = undefined;
      this.activeFencingToken = undefined;
      this.activeAbortController = undefined;
      if (this.state === "PROCESSING") {
        this.state = "READY";
      }
    }
  }

  private async handleHeartbeatRequest(request: BinaryWorkerHeartbeat): Promise<void> {
    const heartbeatResponse: BinaryWorkerHeartbeat = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "HEARTBEAT",
      messageId: randomUUID(),
      workerId: this.workerId,
      timestamp: Date.now(),
      activeTaskId: this.activeTaskId ?? null,
      fencingToken: this.activeFencingToken ?? null,
    };
    await this.writeFrame(heartbeatResponse);
  }

  private async handleCancelRequest(request: BinaryWorkerCancelRequest): Promise<void> {
    let status: "CANCELLED" | "TASK_ALREADY_COMPLETED" | "TASK_NOT_FOUND" = "TASK_NOT_FOUND";

    if (this.activeTaskId === request.taskId) {
      this.writeDiagnostic(`[BinaryWorkerRuntime] Aborting active task ${request.taskId}: ${request.reason}`);
      if (this.activeAbortController) {
        this.activeAbortController.abort();
      }
      status = "CANCELLED";
    }

    await this.writeFrame({
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "CANCEL_ACK",
      messageId: randomUUID(),
      inReplyTo: request.messageId,
      taskId: request.taskId,
      status,
    });
  }

  private async handleShutdownRequest(request: BinaryWorkerShutdownRequest): Promise<void> {
    this.writeDiagnostic(`[BinaryWorkerRuntime] Received graceful shutdown request: ${request.reason}`);
    await this.writeFrame({
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "SHUTDOWN_ACK",
      messageId: randomUUID(),
      inReplyTo: request.messageId,
      workerId: this.workerId,
    });

    await this.shutdown();
  }

  private async sendReadyFrame(): Promise<void> {
    let heapLimitBytes: number | null = null;
    try {
      heapLimitBytes = getHeapStatistics().heap_size_limit;
    } catch {
      // Non-v8 runtime fallback
    }

    const readyFrame: BinaryWorkerReady = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "WORKER_READY",
      messageId: randomUUID(),
      workerId: this.workerId,
      pid: process.pid,
      supportedArchitectures: ["x86_64", "ARM", "ARM32", "Thumb", "MIPS_BE", "MIPS_LE"],
      heapLimitBytes,
    };
    await this.writeFrame(readyFrame);
  }

  private async sendAnalyzeResponse(
    request: BinaryWorkerAnalyzeRequest,
    executionStatus: "SUCCESS" | "PARTIAL" | "FAILED",
    decodeCompleteness: BinaryWorkerAnalyzeResponse["decodeCompleteness"],
    resultPayload: RawAnalysisResultPayload,
    diagnostics: string[],
    resourceUsage?: BinaryWorkerAnalyzeResponse["resourceUsage"],
    providedDigest?: string,
  ): Promise<void> {
    // If digest is not provided, use zero-digest placeholder for failure cases
    const resultDigest =
      providedDigest ||
      "0000000000000000000000000000000000000000000000000000000000000000";

    const response: BinaryWorkerAnalyzeResponse = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_RESPONSE",
      messageId: randomUUID(),
      inReplyTo: request.messageId,
      taskId: request.taskId,
      assessmentId: request.assessmentId,
      assetId: request.assetId,
      firmwareSha256: request.firmwareSha256,
      binarySha256: request.binarySha256,
      runId: request.runId,
      fencingToken: request.fencingToken,
      workerId: this.workerId,
      stage: request.requestedStage,
      executionStatus,
      decodeCompleteness,
      resultPayload,
      resultDigest,
      diagnostics: diagnostics.slice(0, 100),
      resourceUsage: resourceUsage ?? {
        cpuTimeMs: 0,
        peakMemoryBytes: 0,
        wallTimeMs: 0,
      },
    };

    await this.writeFrame(response);
  }

  private async sendErrorFrame(
    code: BinaryWorkerErrorResponse["code"],
    message: string,
    recoverable: boolean,
    inReplyTo?: string,
    taskId?: string,
  ): Promise<void> {
    const errorFrame: BinaryWorkerErrorResponse = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "WORKER_ERROR",
      messageId: randomUUID(),
      inReplyTo,
      taskId,
      code,
      message: sanitizeErrorMessage(message),
      recoverable,
    };
    await this.writeFrame(errorFrame);
  }

  private computeResourceUsage(
    startCpu: NodeJS.CpuUsage,
    startWallMs: number,
  ): BinaryWorkerAnalyzeResponse["resourceUsage"] {
    const cpuDiff = process.cpuUsage(startCpu);
    const cpuTimeMs = Math.round((cpuDiff.user + cpuDiff.system) / 1000);
    const wallTimeMs = Math.round(performance.now() - startWallMs);
    let peakMemoryBytes = 0;
    try {
      peakMemoryBytes = process.memoryUsage().heapUsed;
    } catch {
      // Memory read fallback
    }

    return {
      cpuTimeMs,
      peakMemoryBytes,
      wallTimeMs,
    };
  }

  private async writeFrame(message: BinaryWorkerIpcMessage): Promise<void> {
    const serRes = this.framer.serialize(message);
    if (!serRes.ok) {
      this.writeDiagnostic(`[BinaryWorkerRuntime] Serialization error: ${serRes.error.message}`);
      return;
    }

    await new Promise<void>((resolve, reject) => {
      this.outputStream.write(serRes.value, (errCause) => {
        if (errCause) reject(errCause);
        else resolve();
      });
    });
  }

  private writeDiagnostic(logLine: string): void {
    try {
      this.diagnosticStream.write(`${logLine}\n`);
    } catch {
      // Diagnostic channel must never throw
    }
  }
}
