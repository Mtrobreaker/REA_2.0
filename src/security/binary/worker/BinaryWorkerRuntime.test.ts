/* eslint-disable max-lines-per-function */
import { describe, expect, it } from "vitest";
import { PassThrough } from "node:stream";
import { createHash, randomUUID } from "node:crypto";
import { rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  BinaryWorkerRuntime,
  sanitizeErrorMessage,
} from "./BinaryWorkerRuntime.js";
import {
  BINARY_WORKER_PROTOCOL_VERSION,
  type BinaryWorkerAnalyzeRequest,
  type BinaryWorkerIpcMessage,
} from "../ipc/binaryWorkerProtocol.js";
import { BinaryMessageFramer } from "../ipc/binaryMessageFramer.js";

function frameMessage(msg: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(msg)}\n`, "utf8");
}

async function readFramesFromStream(
  stream: PassThrough,
  expectedCount: number,
  timeoutMs = 3000,
): Promise<BinaryWorkerIpcMessage[]> {
  const framer = new BinaryMessageFramer();
  const frames: BinaryWorkerIpcMessage[] = [];

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Timed out waiting for ${expectedCount} frames; received ${frames.length}`));
    }, timeoutMs);

    stream.on("data", (chunk: Buffer) => {
      const results = framer.push(chunk);
      for (const res of results) {
        if (res.ok) {
          frames.push(res.value);
          if (frames.length >= expectedCount) {
            clearTimeout(timer);
            resolve(frames);
          }
        }
      }
    });
  });
}

describe("REA Phase 3A — Milestone 2: BinaryWorkerRuntime Unit Suite", () => {
  // ARM32 nop instruction: 0x00, 0x00, 0xa0, 0xe1 (mov r0, r0)
  const nopBytes = Buffer.from([0x00, 0x00, 0xa0, 0xe1]);
  const nopSha256 = createHash("sha256").update(nopBytes).digest("hex");
  const validWorkerId = `wkr_${randomUUID().replace(/-/g, "")}`;

  it("TEST-1: Bootstraps runtime, emits WORKER_READY frame, and enters READY state", async () => {
    const inputStream = new PassThrough();
    const outputStream = new PassThrough();
    const diagnosticStream = new PassThrough();

    const runtime = new BinaryWorkerRuntime({
      workerId: validWorkerId,
      inputStream,
      outputStream,
      diagnosticStream,
    });

    const readyPromise = readFramesFromStream(outputStream, 1);
    void runtime.start();

    const frames = await readyPromise;
    const readyFrame = frames[0]!;
    expect(readyFrame).toBeDefined();
    expect(readyFrame.kind).toBe("WORKER_READY");
    if (readyFrame.kind === "WORKER_READY") {
      expect(readyFrame.protocolVersion).toBe(BINARY_WORKER_PROTOCOL_VERSION);
      expect(readyFrame.workerId).toBe(validWorkerId);
      expect(readyFrame.pid).toBe(process.pid);
      expect(readyFrame.supportedArchitectures).toContain("ARM");
      expect(readyFrame.supportedArchitectures).toContain("x86_64");
    }

    expect(runtime.getState()).toBe("READY");
    await runtime.shutdown();
  });

  it("TEST-2: Processes valid ANALYZE_REQUEST with inline buffer for DECODE stage", async () => {
    const inputStream = new PassThrough();
    const outputStream = new PassThrough();
    const diagnosticStream = new PassThrough();

    const runtime = new BinaryWorkerRuntime({
      workerId: validWorkerId,
      inputStream,
      outputStream,
      diagnosticStream,
    });

    void runtime.start();
    // Consume ready frame
    await readFramesFromStream(outputStream, 1);

    const request: BinaryWorkerAnalyzeRequest = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_REQUEST",
      messageId: randomUUID(),
      taskId: "tsk_test_001",
      assessmentId: "asm_test_001",
      assetId: "ast_test_001",
      binarySha256: nopSha256,
      runId: "run_test_001",
      fencingToken: 1,
      workerId: validWorkerId,
      requestedStage: "DECODE",
      binaryInput: {
        type: "inline_buffer",
        expected_sha256: nopSha256,
        byte_size: nopBytes.length,
        data_base64: nopBytes.toString("base64"),
        read_only: true,
      },
      analysisConfiguration: {
        architecture: "ARM",
        entryPoints: ["main"],
        maxInstructions: 1000,
        maxCfgBlocks: 100,
        maxPaths: 10,
      },
      deadline: Date.now() + 60_000,
    };

    const responsePromise = readFramesFromStream(outputStream, 1);
    inputStream.write(frameMessage(request));

    const frames = await responsePromise;
    const response = frames[0]!;
    expect(response).toBeDefined();
    expect(response.kind).toBe("ANALYZE_RESPONSE");
    if (response.kind === "ANALYZE_RESPONSE") {
      expect(response.inReplyTo).toBe(request.messageId);
      expect(response.taskId).toBe(request.taskId);
      expect(response.stage).toBe("DECODE");
      expect(response.executionStatus).toBe("SUCCESS");
      expect(response.decodeCompleteness.isComplete).toBe(true);
      expect(response.resultPayload.decoder).toBeDefined();
      expect(response.resultPayload.decoder?.instructions.length).toBeGreaterThan(0);
      expect(response.resultDigest).toMatch(/^[0-9a-f]{64}$/);
      expect(response.resourceUsage.wallTimeMs).toBeGreaterThanOrEqual(0);
    }

    await runtime.shutdown();
  });

  it("TEST-3: Processes valid ANALYZE_REQUEST for CFG, REACHABILITY, TAINT, and WITNESS stages", async () => {
    const inputStream = new PassThrough();
    const outputStream = new PassThrough();

    const runtime = new BinaryWorkerRuntime({
      workerId: validWorkerId,
      inputStream,
      outputStream,
    });

    void runtime.start();
    await readFramesFromStream(outputStream, 1); // ready frame

    const stages: Array<"CFG" | "REACHABILITY" | "TAINT" | "WITNESS"> = [
      "CFG",
      "REACHABILITY",
      "TAINT",
      "WITNESS",
    ];

    for (let i = 0; i < stages.length; i++) {
      const stage = stages[i]!;
      const request: BinaryWorkerAnalyzeRequest = {
        protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
        kind: "ANALYZE_REQUEST",
        messageId: randomUUID(),
        taskId: `tsk_stage_${i}`,
        assessmentId: "asm_test_001",
        assetId: "ast_test_001",
        binarySha256: nopSha256,
        runId: "run_test_001",
        fencingToken: i + 1,
        workerId: validWorkerId,
        requestedStage: stage,
        binaryInput: {
          type: "inline_buffer",
          expected_sha256: nopSha256,
          byte_size: nopBytes.length,
          data_base64: nopBytes.toString("base64"),
          read_only: true,
        },
        analysisConfiguration: {
          architecture: "ARM",
          entryPoints: ["main"],
          targetFunctions: ["system"],
          maxInstructions: 1000,
          maxCfgBlocks: 100,
          maxPaths: 10,
        },
        deadline: Date.now() + 60_000,
      };

      const responsePromise = readFramesFromStream(outputStream, 1);
      inputStream.write(frameMessage(request));
      const respFrames = await responsePromise;
      const response = respFrames[0]!;

      expect(response).toBeDefined();
      expect(response.kind).toBe("ANALYZE_RESPONSE");
      if (response.kind === "ANALYZE_RESPONSE") {
        expect(response.stage).toBe(stage);
        expect(response.executionStatus).toBe("SUCCESS");
        expect(response.resultDigest).toMatch(/^[0-9a-f]{64}$/);
      }
    }

    await runtime.shutdown();
  });

  it("TEST-4: Rejects request with worker ID mismatch", async () => {
    const inputStream = new PassThrough();
    const outputStream = new PassThrough();

    const runtime = new BinaryWorkerRuntime({
      workerId: validWorkerId,
      inputStream,
      outputStream,
    });

    void runtime.start();
    await readFramesFromStream(outputStream, 1);

    const otherWorkerId = `wkr_${randomUUID().replace(/-/g, "")}`;
    const request: BinaryWorkerAnalyzeRequest = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_REQUEST",
      messageId: randomUUID(),
      taskId: "tsk_mismatch",
      assessmentId: "asm_test_001",
      assetId: "ast_test_001",
      binarySha256: nopSha256,
      runId: "run_test_001",
      fencingToken: 1,
      workerId: otherWorkerId,
      requestedStage: "DECODE",
      binaryInput: {
        type: "inline_buffer",
        expected_sha256: nopSha256,
        byte_size: nopBytes.length,
        data_base64: nopBytes.toString("base64"),
        read_only: true,
      },
      analysisConfiguration: {
        architecture: "ARM",
        entryPoints: ["main"],
        maxInstructions: 1000,
        maxCfgBlocks: 100,
        maxPaths: 10,
      },
      deadline: Date.now() + 60_000,
    };

    const responsePromise = readFramesFromStream(outputStream, 1);
    inputStream.write(frameMessage(request));

    const errFrames = await responsePromise;
    const errorFrame = errFrames[0]!;
    expect(errorFrame).toBeDefined();
    expect(errorFrame.kind).toBe("WORKER_ERROR");
    if (errorFrame.kind === "WORKER_ERROR") {
      expect(errorFrame.code).toBe("MALFORMED_REQUEST");
      expect(errorFrame.message).toContain("Target worker ID does not match");
    }

    await runtime.shutdown();
  });

  it("TEST-5: Rejects request with expired deadline before start", async () => {
    const inputStream = new PassThrough();
    const outputStream = new PassThrough();

    const runtime = new BinaryWorkerRuntime({
      workerId: validWorkerId,
      inputStream,
      outputStream,
    });

    void runtime.start();
    await readFramesFromStream(outputStream, 1);

    const request: BinaryWorkerAnalyzeRequest = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_REQUEST",
      messageId: randomUUID(),
      taskId: "tsk_expired",
      assessmentId: "asm_test_001",
      assetId: "ast_test_001",
      binarySha256: nopSha256,
      runId: "run_test_001",
      fencingToken: 1,
      workerId: validWorkerId,
      requestedStage: "DECODE",
      binaryInput: {
        type: "inline_buffer",
        expected_sha256: nopSha256,
        byte_size: nopBytes.length,
        data_base64: nopBytes.toString("base64"),
        read_only: true,
      },
      analysisConfiguration: {
        architecture: "ARM",
        entryPoints: ["main"],
        maxInstructions: 1000,
        maxCfgBlocks: 100,
        maxPaths: 10,
      },
      deadline: Date.now() - 5000, // already expired
    };

    const responsePromise = readFramesFromStream(outputStream, 1);
    inputStream.write(frameMessage(request));

    const respFrames = await responsePromise;
    const response = respFrames[0]!;
    expect(response).toBeDefined();
    expect(response.kind).toBe("ANALYZE_RESPONSE");
    if (response.kind === "ANALYZE_RESPONSE") {
      expect(response.executionStatus).toBe("FAILED");
      expect(response.decodeCompleteness.isComplete).toBe(false);
      expect(response.decodeCompleteness.haltReason).toContain("deadline expired");
    }

    await runtime.shutdown();
  });

  it("TEST-6: Rejects binary input with SHA-256 digest mismatch", async () => {
    const inputStream = new PassThrough();
    const outputStream = new PassThrough();

    const runtime = new BinaryWorkerRuntime({
      workerId: validWorkerId,
      inputStream,
      outputStream,
    });

    void runtime.start();
    await readFramesFromStream(outputStream, 1);

    const forgedDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const request: BinaryWorkerAnalyzeRequest = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_REQUEST",
      messageId: randomUUID(),
      taskId: "tsk_digest_mismatch",
      assessmentId: "asm_test_001",
      assetId: "ast_test_001",
      binarySha256: forgedDigest,
      runId: "run_test_001",
      fencingToken: 1,
      workerId: validWorkerId,
      requestedStage: "DECODE",
      binaryInput: {
        type: "inline_buffer",
        expected_sha256: forgedDigest, // does not match actual bytes
        byte_size: nopBytes.length,
        data_base64: nopBytes.toString("base64"),
        read_only: true,
      },
      analysisConfiguration: {
        architecture: "ARM",
        entryPoints: ["main"],
        maxInstructions: 1000,
        maxCfgBlocks: 100,
        maxPaths: 10,
      },
      deadline: Date.now() + 60_000,
    };

    const responsePromise = readFramesFromStream(outputStream, 1);
    inputStream.write(frameMessage(request));

    const respFrames = await responsePromise;
    const response = respFrames[0]!;
    expect(response).toBeDefined();
    expect(response.kind).toBe("ANALYZE_RESPONSE");
    if (response.kind === "ANALYZE_RESPONSE") {
      expect(response.executionStatus).toBe("FAILED");
      expect(response.decodeCompleteness.haltReason).toContain("digest mismatch");
    }

    await runtime.shutdown();
  });

  it("TEST-7: Rejects file_path binary input with path traversal or root escape", async () => {
    const testDir = join(tmpdir(), `rea_test_sandbox_${randomUUID()}`);
    await mkdir(testDir, { recursive: true });

    const inputStream = new PassThrough();
    const outputStream = new PassThrough();

    const runtime = new BinaryWorkerRuntime({
      workerId: validWorkerId,
      allowedRoot: testDir,
      inputStream,
      outputStream,
    });

    void runtime.start();
    await readFramesFromStream(outputStream, 1);

    const escapePath = join(testDir, "..", "escaped.bin");
    const request: BinaryWorkerAnalyzeRequest = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_REQUEST",
      messageId: randomUUID(),
      taskId: "tsk_traversal",
      assessmentId: "asm_test_001",
      assetId: "ast_test_001",
      binarySha256: nopSha256,
      runId: "run_test_001",
      fencingToken: 1,
      workerId: validWorkerId,
      requestedStage: "DECODE",
      binaryInput: {
        type: "file_path",
        path: escapePath,
        expected_sha256: nopSha256,
        byte_size: nopBytes.length,
        read_only: true,
      },
      analysisConfiguration: {
        architecture: "ARM",
        entryPoints: ["main"],
        maxInstructions: 1000,
        maxCfgBlocks: 100,
        maxPaths: 10,
      },
      deadline: Date.now() + 60_000,
    };

    const responsePromise = readFramesFromStream(outputStream, 1);
    inputStream.write(frameMessage(request));

    const respFrames = await responsePromise;
    const response = respFrames[0]!;
    expect(response).toBeDefined();
    expect(response.kind).toBe("ANALYZE_RESPONSE");
    if (response.kind === "ANALYZE_RESPONSE") {
      expect(response.executionStatus).toBe("FAILED");
      expect(response.decodeCompleteness.haltReason).toContain("traversal");
    }

    await runtime.shutdown();
    await rm(testDir, { recursive: true, force: true });
  });

  it("TEST-8: Handles HEARTBEAT message and reflects active task state", async () => {
    const inputStream = new PassThrough();
    const outputStream = new PassThrough();

    const runtime = new BinaryWorkerRuntime({
      workerId: validWorkerId,
      inputStream,
      outputStream,
    });

    void runtime.start();
    await readFramesFromStream(outputStream, 1);

    const heartbeatReq = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "HEARTBEAT",
      messageId: randomUUID(),
      workerId: validWorkerId,
      timestamp: Date.now(),
      activeTaskId: null,
      fencingToken: null,
    };

    const responsePromise = readFramesFromStream(outputStream, 1);
    inputStream.write(frameMessage(heartbeatReq));

    const respFrames = await responsePromise;
    const heartbeatResp = respFrames[0]!;
    expect(heartbeatResp).toBeDefined();
    expect(heartbeatResp.kind).toBe("HEARTBEAT");
    if (heartbeatResp.kind === "HEARTBEAT") {
      expect(heartbeatResp.workerId).toBe(validWorkerId);
      expect(heartbeatResp.activeTaskId).toBeNull();
      expect(heartbeatResp.timestamp).toBeGreaterThan(0);
    }

    await runtime.shutdown();
  });

  it("TEST-9: Handles CANCEL message and responds with CANCEL_ACK", async () => {
    const inputStream = new PassThrough();
    const outputStream = new PassThrough();

    const runtime = new BinaryWorkerRuntime({
      workerId: validWorkerId,
      inputStream,
      outputStream,
    });

    void runtime.start();
    await readFramesFromStream(outputStream, 1);

    const cancelReq = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "CANCEL",
      messageId: randomUUID(),
      taskId: "tsk_non_existent",
      reason: "Analysis aborted by user",
    };

    const responsePromise = readFramesFromStream(outputStream, 1);
    inputStream.write(frameMessage(cancelReq));

    const respFrames = await responsePromise;
    const cancelAck = respFrames[0]!;
    expect(cancelAck).toBeDefined();
    expect(cancelAck.kind).toBe("CANCEL_ACK");
    if (cancelAck.kind === "CANCEL_ACK") {
      expect(cancelAck.taskId).toBe("tsk_non_existent");
      expect(cancelAck.status).toBe("TASK_NOT_FOUND");
    }

    await runtime.shutdown();
  });

  it("TEST-10: Handles SHUTDOWN message with SHUTDOWN_ACK and clean state transition", async () => {
    const inputStream = new PassThrough();
    const outputStream = new PassThrough();

    const runtime = new BinaryWorkerRuntime({
      workerId: validWorkerId,
      inputStream,
      outputStream,
    });

    const startPromise = runtime.start();
    await readFramesFromStream(outputStream, 1);

    const shutdownReq = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "SHUTDOWN",
      messageId: randomUUID(),
      reason: "Routine cluster rotation",
      gracePeriodMs: 500,
    };

    const responsePromise = readFramesFromStream(outputStream, 1);
    inputStream.write(frameMessage(shutdownReq));

    const respFrames = await responsePromise;
    const shutdownAck = respFrames[0]!;
    expect(shutdownAck).toBeDefined();
    expect(shutdownAck.kind).toBe("SHUTDOWN_ACK");
    if (shutdownAck.kind === "SHUTDOWN_ACK") {
      expect(shutdownAck.workerId).toBe(validWorkerId);
    }

    await startPromise;
    expect(runtime.getState()).toBe("TERMINATED");
  });

  it("TEST-11: Detects parent disconnect on stdin EOF and terminates gracefully", async () => {
    const inputStream = new PassThrough();
    const outputStream = new PassThrough();

    const runtime = new BinaryWorkerRuntime({
      workerId: validWorkerId,
      inputStream,
      outputStream,
    });

    const startPromise = runtime.start();
    await readFramesFromStream(outputStream, 1);

    // Close stdin pipe
    inputStream.end();

    await startPromise;
    expect(runtime.getState()).toBe("TERMINATED");
  });

  it("TEST-12: Error message sanitation removes filesystem paths and stack traces", () => {
    const rawError = "Error: Failed to read C:\\Users\\Administrator\\secret\\firmware.bin\n    at Object.readFile (node:fs:123:45)";
    const sanitized = sanitizeErrorMessage(rawError);
    expect(sanitized).not.toContain("C:\\Users");
    expect(sanitized).not.toContain("Administrator");
    expect(sanitized).not.toContain("node:fs");
    expect(sanitized).toContain("<redacted_path>");
  });

  it("TEST-13: Verifies child runtime does not import or hold database or evidence signing authority", () => {
    const runtime = new BinaryWorkerRuntime({ workerId: validWorkerId });
    expect((runtime as any).keyring).toBeUndefined();
    expect((runtime as any).keyringManager).toBeUndefined();
    expect((runtime as any).evidenceSealer).toBeUndefined();
    expect((runtime as any).sqlite).toBeUndefined();
    expect((runtime as any).blackboard).toBeUndefined();
  });
});
