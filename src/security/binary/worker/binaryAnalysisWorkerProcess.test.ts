/* eslint-disable max-lines-per-function */
import { describe, expect, it } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { BinaryMessageFramer } from "../ipc/binaryMessageFramer.js";
import {
  BINARY_WORKER_PROTOCOL_VERSION,
  type BinaryWorkerAnalyzeRequest,
  type BinaryWorkerIpcMessage,
} from "../ipc/binaryWorkerProtocol.js";

function frameMessage(msg: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(msg)}\n`, "utf8");
}

function createChildReader(child: ChildProcess) {
  const framer = new BinaryMessageFramer();
  const queue: BinaryWorkerIpcMessage[] = [];
  const waiters: Array<(msg: BinaryWorkerIpcMessage) => void> = [];
  let stdoutRaw = "";
  let stderrRaw = "";

  child.stdout?.on("data", (chunk: Buffer) => {
    stdoutRaw += chunk.toString("utf8");
    const results = framer.push(chunk);
    for (const res of results) {
      if (res.ok) {
        if (waiters.length > 0) {
          const waiter = waiters.shift()!;
          waiter(res.value);
        } else {
          queue.push(res.value);
        }
      }
    }
  });

  child.stderr?.on("data", (chunk: Buffer) => {
    stderrRaw += chunk.toString("utf8");
  });

  return {
    async readNext(timeoutMs = 5000): Promise<BinaryWorkerIpcMessage> {
      if (queue.length > 0) {
        return queue.shift()!;
      }
      return new Promise<BinaryWorkerIpcMessage>((resolve, reject) => {
        const timer = setTimeout(() => {
          reject(
            new Error(
              `Timed out after ${timeoutMs}ms waiting for frame from child.\nStdout observed: ${stdoutRaw}\nStderr observed: ${stderrRaw}`,
            ),
          );
        }, timeoutMs);

        waiters.push((msg) => {
          clearTimeout(timer);
          resolve(msg);
        });
      });
    },
    getStdoutRaw: () => stdoutRaw,
    getStderrRaw: () => stderrRaw,
  };
}

describe("REA Phase 3A — Milestone 2: Child Process Integration Suite", () => {
  const nopBytes = Buffer.from([0x00, 0x00, 0xa0, 0xe1]);
  const nopSha256 = createHash("sha256").update(nopBytes).digest("hex");
  const testWorkerId = `wkr_int_${randomUUID().replace(/-/g, "")}`;

  it("REAL-CHILD-1: Spawns binaryAnalysisWorkerProcess, completes handshake, processes requests, and shuts down cleanly", async () => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "src/composition/binaryAnalysisWorkerProcess.ts"],
      {
        stdio: ["pipe", "pipe", "pipe"],
        env: {
          ...process.env,
          REA_BINARY_WORKER_ID: testWorkerId,
        },
      },
    );

    const reader = createChildReader(child);

    // 1. Initial Handshake: WORKER_READY
    const readyFrame = await reader.readNext();
    expect(readyFrame.kind).toBe("WORKER_READY");
    if (readyFrame.kind === "WORKER_READY") {
      expect(readyFrame.workerId).toBe(testWorkerId);
      expect(readyFrame.pid).toBe(child.pid);
      expect(readyFrame.protocolVersion).toBe(BINARY_WORKER_PROTOCOL_VERSION);
    }

    // 2. Dispatch ANALYZE_REQUEST for DECODE stage
    const req1: BinaryWorkerAnalyzeRequest = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_REQUEST",
      messageId: randomUUID(),
      taskId: "tsk_real_child_01",
      assessmentId: "asm_real_01",
      assetId: "ast_real_01",
      binarySha256: nopSha256,
      runId: "run_real_01",
      fencingToken: 1,
      workerId: testWorkerId,
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
        maxInstructions: 500,
        maxCfgBlocks: 50,
        maxPaths: 5,
      },
      deadline: Date.now() + 60_000,
    };

    child.stdin?.write(frameMessage(req1));
    const resp1 = await reader.readNext();

    expect(resp1.kind).toBe("ANALYZE_RESPONSE");
    if (resp1.kind === "ANALYZE_RESPONSE") {
      expect(resp1.inReplyTo).toBe(req1.messageId);
      expect(resp1.taskId).toBe(req1.taskId);
      expect(resp1.stage).toBe("DECODE");
      expect(resp1.executionStatus).toBe("SUCCESS");
      expect(resp1.resultPayload.decoder).toBeDefined();
      expect(resp1.resultDigest).toMatch(/^[0-9a-f]{64}$/);
    }

    // 3. Heartbeat Query
    const hbReq = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "HEARTBEAT",
      messageId: randomUUID(),
      workerId: testWorkerId,
      timestamp: Date.now(),
      activeTaskId: null,
      fencingToken: null,
    };

    child.stdin?.write(frameMessage(hbReq));
    const hbResp = await reader.readNext();

    expect(hbResp.kind).toBe("HEARTBEAT");
    if (hbResp.kind === "HEARTBEAT") {
      expect(hbResp.workerId).toBe(testWorkerId);
      expect(hbResp.activeTaskId).toBeNull();
    }

    // 4. Sequential Request for CFG stage
    const req2: BinaryWorkerAnalyzeRequest = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_REQUEST",
      messageId: randomUUID(),
      taskId: "tsk_real_child_02",
      assessmentId: "asm_real_01",
      assetId: "ast_real_01",
      binarySha256: nopSha256,
      runId: "run_real_01",
      fencingToken: 2,
      workerId: testWorkerId,
      requestedStage: "CFG",
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
        maxInstructions: 500,
        maxCfgBlocks: 50,
        maxPaths: 5,
      },
      deadline: Date.now() + 60_000,
    };

    child.stdin?.write(frameMessage(req2));
    const resp2 = await reader.readNext();

    expect(resp2.kind).toBe("ANALYZE_RESPONSE");
    if (resp2.kind === "ANALYZE_RESPONSE") {
      expect(resp2.stage).toBe("CFG");
      expect(resp2.executionStatus).toBe("SUCCESS");
      expect(resp2.resultPayload.cfg).toBeDefined();
    }

    // 5. Graceful SHUTDOWN
    const shutdownReq = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "SHUTDOWN",
      messageId: randomUUID(),
      reason: "Integration test completed",
      gracePeriodMs: 500,
    };

    child.stdin?.write(frameMessage(shutdownReq));
    const shutdownAck = await reader.readNext();

    expect(shutdownAck.kind).toBe("SHUTDOWN_ACK");
    if (shutdownAck.kind === "SHUTDOWN_ACK") {
      expect(shutdownAck.workerId).toBe(testWorkerId);
    }

    // 6. Child Process Exit Verification
    const exitCode = await new Promise<number | null>((resolve) => {
      child.on("exit", (code) => resolve(code));
    });

    expect(exitCode).toBe(0);

    // 7. Stdio Cleanliness Verification
    // Stderr must have received diagnostics
    expect(reader.getStderrRaw()).toContain("[BinaryWorkerRuntime]");
    // Stdout must not contain debug strings like "[BinaryWorkerRuntime]"
    expect(reader.getStdoutRaw()).not.toContain("[BinaryWorkerRuntime]");
  });

  it("REAL-CHILD-2: Child terminates deterministically on parent stdin EOF without hanging", async () => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "src/composition/binaryAnalysisWorkerProcess.ts"],
      {
        stdio: ["pipe", "pipe", "pipe"],
      },
    );

    const reader = createChildReader(child);

    // Wait for ready frame
    const readyFrame = await reader.readNext();
    expect(readyFrame.kind).toBe("WORKER_READY");

    // Close stdin pipe abruptly (simulating parent death / unbind)
    child.stdin?.end();

    const exitCode = await new Promise<number | null>((resolve) => {
      const timer = setTimeout(() => {
        child.kill();
        resolve(-999);
      }, 5000);

      child.on("exit", (code) => {
        clearTimeout(timer);
        resolve(code);
      });
    });

    expect(exitCode).toBe(0);
    expect(reader.getStderrRaw()).toContain("Stdin reached EOF");
  });
});
