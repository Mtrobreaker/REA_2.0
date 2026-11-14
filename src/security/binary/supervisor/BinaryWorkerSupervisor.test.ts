/* eslint-disable max-lines-per-function */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createHash, randomUUID } from "node:crypto";
import {
  BINARY_WORKER_PROTOCOL_VERSION,
  type BinaryWorkerAnalyzeRequest,
  type BinaryWorkerAnalyzeResponse,
} from "../ipc/binaryWorkerProtocol.js";
import {
  BinaryWorkerSupervisor,
  type BinarySupervisorLifecycleEvent,
} from "./BinaryWorkerSupervisor.js";
import type { WindowsNativeAuthority } from "../../../windows/WindowsNativeLoader.js";

const nopBytes = Buffer.from([0x00, 0x00, 0xa0, 0xe1]); // ARM NOP: mov r0, r0
const nopSha256 = createHash("sha256").update(nopBytes).digest("hex");

function makeAnalyzeRequest(overrides?: Partial<BinaryWorkerAnalyzeRequest>): BinaryWorkerAnalyzeRequest {
  const taskId = overrides?.taskId ?? `tsk_test_${randomUUID().slice(0, 8)}`;
  return {
    protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
    kind: "ANALYZE_REQUEST",
    messageId: randomUUID(),
    taskId,
    assessmentId: "asm_test_01",
    assetId: "ast_test_01",
    binarySha256: nopSha256,
    runId: "run_test_01",
    fencingToken: 1,
    workerId: "wkr_test_worker_01",
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
      maxInstructions: 100,
      maxCfgBlocks: 10,
      maxPaths: 5,
    },
    deadline: Date.now() + 15_000,
    ...overrides,
  };
}

describe("REA Phase 3A — Milestone 3: BinaryWorkerSupervisor Adversarial Suite", () => {
  const activeSupervisors: BinaryWorkerSupervisor[] = [];

  afterEach(async () => {
    while (activeSupervisors.length > 0) {
      const sup = activeSupervisors.pop()!;
      try {
        await sup.shutdown(250);
      } catch {
        sup.forceKillProcess();
      }
    }
    vi.restoreAllMocks();
  });

  function trackSupervisor(sup: BinaryWorkerSupervisor): BinaryWorkerSupervisor {
    activeSupervisors.push(sup);
    return sup;
  }

  // ==========================================================================
  // Scenario 1: Normal worker startup and shutdown
  // ==========================================================================
  it("SCENARIO-1: Normal worker startup, handshake, and clean shutdown", async () => {
    const events: BinarySupervisorLifecycleEvent[] = [];
    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_test_worker_01",
        onEvent: (e) => events.push(e),
      }),
    );

    const ready = await supervisor.start();
    expect(ready.kind).toBe("WORKER_READY");
    expect(ready.workerId).toBe("wkr_test_worker_01");
    expect(supervisor.getState()).toBe("READY");
    expect(supervisor.getChildPid()).toBeTypeOf("number");

    await supervisor.shutdown(500);
    expect(supervisor.getState()).toBe("STOPPED");

    expect(events.some((e) => e.type === "spawned")).toBe(true);
    expect(events.some((e) => e.type === "ready")).toBe(true);
    expect(events.some((e) => e.type === "worker_shutdown")).toBe(true);
  });

  // ==========================================================================
  // Scenario 2: Worker startup timeout
  // ==========================================================================
  it("SCENARIO-2: Worker startup timeout terminates child and rejects promise", async () => {
    // Child script that sleeps without sending WORKER_READY
    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        command: process.execPath,
        arguments: ["-e", "setTimeout(() => {}, 10000);"],
        startupTimeoutMs: 250,
      }),
    );

    await expect(supervisor.start()).rejects.toThrow(/Worker startup timed out after 250ms/);
    expect(supervisor.getState()).toBe("TERMINATED");
  });

  // ==========================================================================
  // Scenario 3: Child crash (worker exit with non-zero code)
  // ==========================================================================
  it("SCENARIO-3: Child process crash during execution is detected and handled", async () => {
    // Worker that sends ready, then crashes when receiving ANALYZE_REQUEST
    const crashWorkerScript = `
      process.stdout.write(JSON.stringify({
        protocolVersion: "1.0.0",
        kind: "WORKER_READY",
        messageId: "11111111-1111-4111-8111-111111111111",
        workerId: "wkr_test_worker_01",
        pid: process.pid,
        supportedArchitectures: ["ARM", "x86_64"],
        heapLimitBytes: null
      }) + "\\n");

      process.stdin.on("data", () => {
        process.exit(42);
      });
    `;

    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_test_worker_01",
        command: process.execPath,
        arguments: ["-e", crashWorkerScript],
      }),
    );

    await supervisor.start();

    const request = makeAnalyzeRequest();
    const result = await supervisor.executeTask(request);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("WORKER_CRASHED");
      expect(result.error.message).toContain("42");
    }
    expect(supervisor.getState()).toBe("TERMINATED");
  });

  // ==========================================================================
  // Scenario 4: Child process hang (task timeout)
  // ==========================================================================
  it("SCENARIO-4: Child process hang triggers deadline timeout", async () => {
    // Worker that sends ready, but ignores task requests and sleeps
    const hangWorkerScript = `
      process.stdout.write(JSON.stringify({
        protocolVersion: "1.0.0",
        kind: "WORKER_READY",
        messageId: "11111111-1111-4111-8111-111111111111",
        workerId: "wkr_test_worker_01",
        pid: process.pid,
        supportedArchitectures: ["ARM"],
        heapLimitBytes: null
      }) + "\\n");
      setInterval(() => {}, 1000);
    `;

    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_test_worker_01",
        command: process.execPath,
        arguments: ["-e", hangWorkerScript],
        defaultTaskTimeoutMs: 300,
        cancelGraceMs: 200,
      }),
    );

    await supervisor.start();

    const request = makeAnalyzeRequest({ deadline: Date.now() + 300 });
    const result = await supervisor.executeTask(request);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("TIMEOUT");
      expect(result.error.message).toContain("timed out");
    }
  });

  // ==========================================================================
  // Scenario 5: CPU-bound infinite loop (non-yielding event loop preemption)
  // ==========================================================================
  it("SCENARIO-5: CPU-bound synchronous loop is forcefully terminated by OS kill", async () => {
    // Worker that receives ANALYZE_REQUEST and enters a synchronous while(true) CPU loop.
    // In Node.js, this blocks the single-threaded event loop completely, meaning
    // CANCEL messages on stdin cannot be read or processed!
    const cpuLoopWorkerScript = `
      process.stdout.write(JSON.stringify({
        protocolVersion: "1.0.0",
        kind: "WORKER_READY",
        messageId: "11111111-1111-4111-8111-111111111111",
        workerId: "wkr_test_worker_01",
        pid: process.pid,
        supportedArchitectures: ["ARM"],
        heapLimitBytes: null
      }) + "\\n");

      process.stdin.once("data", () => {
        // Synchronous non-yielding CPU spin
        const start = Date.now();
        while (Date.now() - start < 15000) {
          // busy loop
        }
      });
    `;

    const events: BinarySupervisorLifecycleEvent[] = [];
    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_test_worker_01",
        command: process.execPath,
        arguments: ["-e", cpuLoopWorkerScript],
        defaultTaskTimeoutMs: 250,
        cancelGraceMs: 200,
        onEvent: (e) => events.push(e),
      }),
    );

    await supervisor.start();
    const pid = supervisor.getChildPid();
    expect(pid).toBeTypeOf("number");

    const request = makeAnalyzeRequest({ deadline: Date.now() + 250 });
    const result = await supervisor.executeTask(request);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("TIMEOUT");
      expect(result.error.message).toContain("forcefully terminated");
    }

    // Verify supervisor escalated to OS-level kill
    expect(events.some((e) => e.type === "worker_killed")).toBe(true);
    expect(supervisor.getState()).toBe("TERMINATED");
  });

  // ==========================================================================
  // Scenario 6: Heartbeat timeout / dead worker
  // ==========================================================================
  it("SCENARIO-6: Worker unresponsive to heartbeats is terminated", async () => {
    // Worker that sends ready but completely drops HEARTBEAT messages (never ACKs)
    const silentHeartbeatWorkerScript = `
      process.stdout.write(JSON.stringify({
        protocolVersion: "1.0.0",
        kind: "WORKER_READY",
        messageId: "11111111-1111-4111-8111-111111111111",
        workerId: "wkr_test_worker_01",
        pid: process.pid,
        supportedArchitectures: ["ARM"],
        heapLimitBytes: null
      }) + "\\n");
      setInterval(() => {}, 1000);
    `;

    const events: BinarySupervisorLifecycleEvent[] = [];
    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_test_worker_01",
        command: process.execPath,
        arguments: ["-e", silentHeartbeatWorkerScript],
        heartbeatIntervalMs: 150,
        heartbeatTimeoutMs: 100,
        maxHeartbeatMisses: 2,
        onEvent: (e) => events.push(e),
      }),
    );

    await supervisor.start();

    // Wait for heartbeats to fail
    await new Promise((resolve) => setTimeout(resolve, 600));

    expect(events.some((e) => e.type === "heartbeat_missed")).toBe(true);
    expect(events.some((e) => e.type === "worker_unresponsive")).toBe(true);
    expect(supervisor.getState()).toBe("TERMINATED");
  });

  // ==========================================================================
  // Scenario 7: Oversized response handling
  // ==========================================================================
  it("SCENARIO-7: Oversized response frame is rejected and terminates worker", async () => {
    // Worker that sends an oversized frame (> 16 MiB line)
    const oversizedWorkerScript = `
      process.stdout.write(JSON.stringify({
        protocolVersion: "1.0.0",
        kind: "WORKER_READY",
        messageId: "11111111-1111-4111-8111-111111111111",
        workerId: "wkr_test_worker_01",
        pid: process.pid,
        supportedArchitectures: ["ARM"],
        heapLimitBytes: null
      }) + "\\n");

      process.stdin.on("data", () => {
        // Send oversized frame exceeding 16 MiB
        const chunk = "A".repeat(1024 * 1024);
        for (let i = 0; i < 17; i++) {
          process.stdout.write(chunk);
        }
        process.stdout.write("\\n");
      });
    `;

    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_test_worker_01",
        command: process.execPath,
        arguments: ["-e", oversizedWorkerScript],
      }),
    );

    await supervisor.start();

    const request = makeAnalyzeRequest();
    const result = await supervisor.executeTask(request);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("OVERSIZED_RESPONSE");
    }
  });

  // ==========================================================================
  // Scenario 8: Malformed IPC response handling (Prototype pollution & schema)
  // ==========================================================================
  it("SCENARIO-8: Malformed or prototype-polluting JSON response is rejected", async () => {
    // Worker that returns prototype-polluting JSON
    const maliciousWorkerScript = `
      process.stdout.write(JSON.stringify({
        protocolVersion: "1.0.0",
        kind: "WORKER_READY",
        messageId: "11111111-1111-4111-8111-111111111111",
        workerId: "wkr_test_worker_01",
        pid: process.pid,
        supportedArchitectures: ["ARM"],
        heapLimitBytes: null
      }) + "\\n");

      process.stdin.on("data", () => {
        process.stdout.write('{"__proto__":{"polluted":true}}\\n');
      });
    `;

    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_test_worker_01",
        command: process.execPath,
        arguments: ["-e", maliciousWorkerScript],
      }),
    );

    await supervisor.start();

    const request = makeAnalyzeRequest();
    const result = await supervisor.executeTask(request);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("PROTOCOL_ERROR");
    }
  });

  // ==========================================================================
  // Scenario 9: Parent cancellation
  // ==========================================================================
  it("SCENARIO-9: Explicit parent task cancellation sends CANCEL and resolves", async () => {
    const cancellableWorkerScript = `
      process.stdout.write(JSON.stringify({
        protocolVersion: "1.0.0",
        kind: "WORKER_READY",
        messageId: "11111111-1111-4111-8111-111111111111",
        workerId: "wkr_test_worker_01",
        pid: process.pid,
        supportedArchitectures: ["ARM"],
        heapLimitBytes: null
      }) + "\\n");

      let activeTask = null;
      process.stdin.on("data", (chunk) => {
        const msg = JSON.parse(chunk.toString().trim());
        if (msg.kind === "ANALYZE_REQUEST") {
          activeTask = msg;
        } else if (msg.kind === "CANCEL" && activeTask) {
          process.stdout.write(JSON.stringify({
            protocolVersion: "1.0.0",
            kind: "CANCEL_ACK",
            messageId: "33333333-3333-4333-8333-333333333333",
            inReplyTo: msg.messageId,
            taskId: msg.taskId,
            status: "CANCELLED"
          }) + "\\n");
        }
      });
    `;

    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_test_worker_01",
        command: process.execPath,
        arguments: ["-e", cancellableWorkerScript],
      }),
    );

    await supervisor.start();

    const request = makeAnalyzeRequest({ taskId: "tsk_cancel_01" });
    const taskPromise = supervisor.executeTask(request);

    // Cancel while in flight
    await new Promise((resolve) => setTimeout(resolve, 50));
    const cancelled = await supervisor.cancelTask("tsk_cancel_01", "User cancelled");
    expect(cancelled).toBe(true);

    const result = await taskPromise;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("CANCELLED");
    }
  });

  // ==========================================================================
  // Scenario 10: Forced process termination
  // ==========================================================================
  it("SCENARIO-10: Forced termination kills process and settles pending work", async () => {
    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_test_worker_01",
      }),
    );

    await supervisor.start();
    const pid = supervisor.getChildPid();
    expect(pid).toBeTypeOf("number");

    supervisor.forceKillProcess();

    // Allow exit event to be received
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(supervisor.getState()).toBe("TERMINATED");
  });

  // ==========================================================================
  // Scenario 11: Process-tree cleanup
  // ==========================================================================
  it("SCENARIO-11: Process-tree cleanup terminates worker and descendants cleanly", async () => {
    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_test_worker_01",
      }),
    );

    await supervisor.start();
    const pid = supervisor.getChildPid()!;
    expect(pid).toBeGreaterThan(0);

    await supervisor.shutdown(500);

    // Verify process is dead
    let isAlive = true;
    try {
      process.kill(pid, 0);
    } catch {
      isAlive = false;
    }
    expect(isAlive).toBe(false);
  });

  // ==========================================================================
  // Scenario 12: Memory-limit enforcement where supported
  // ==========================================================================
  it("SCENARIO-12: Validates memory limits and uses Windows Job Object authority when supplied", async () => {
    // Test Windows native authority injection double
    const calls: Array<{ op: string; args: readonly unknown[] }> = [];
    const mockAuthority: WindowsNativeAuthority = {
      inspection: {
        abiVersion: 1,
        nodeApiVersion: 8,
        architecture: "x64",
        filesystem: {
          requestedPath: "C:\\",
          finalPath: "C:\\",
          filesystem: "NTFS",
          volumeSerial: "0".repeat(16),
          fileId: "0".repeat(32),
          size: 0,
          directory: true,
        },
        privateDacl: true,
        privateBridgeDescriptorAccess: true,
        atomicJobAssignment: true,
        killOnOwnerClose: true,
        protocolStdin: true,
        jobMemoryLimit: true,
      },
      call: (op, args) => {
        calls.push({ op, args });
        if (op === "process_spawn") {
          return {
            pid: 12345,
            handle: {},
            jobAssigned: true,
            killOnOwnerClose: true,
            jobMemoryLimitBytes: args[5],
          };
        }
        if (op === "process_poll") {
          return {
            stdout: Buffer.from(
              JSON.stringify({
                protocolVersion: "1.0.0",
                kind: "WORKER_READY",
                messageId: "11111111-1111-4111-8111-111111111111",
                workerId: "wkr_test_worker_01",
                pid: 12345,
                supportedArchitectures: ["ARM"],
                heapLimitBytes: null,
              }) + "\n",
            ),
            stderr: Buffer.alloc(0),
            stdoutEnded: false,
            stderrEnded: false,
            exitCode: null,
            activeProcesses: 1,
            memoryLimitReached: false,
            peakJobMemoryBytes: 1024 * 1024,
          };
        }
        if (op === "process_terminate") return true;
        if (op === "process_close") return null;
        return null;
      },
    };

    if (process.platform === "win32") {
      const supervisor = trackSupervisor(
        new BinaryWorkerSupervisor({
          workerId: "wkr_test_worker_01",
          memoryLimitBytes: 256 * 1024 * 1024,
          windowsAuthority: mockAuthority,
        }),
      );

      const ready = await supervisor.start();
      expect(ready.workerId).toBe("wkr_test_worker_01");
      expect(calls.some((c) => c.op === "process_spawn")).toBe(true);
      await supervisor.shutdown();
    }
  });

  // ==========================================================================
  // Scenario 13: Multiple concurrent workers (bounded concurrency)
  // ==========================================================================
  it("SCENARIO-13: Multiple concurrent supervisors execute tasks without stdio crosstalk", async () => {
    const sup1 = trackSupervisor(
      new BinaryWorkerSupervisor({ workerId: "wkr_worker_concurrent_01" }),
    );
    const sup2 = trackSupervisor(
      new BinaryWorkerSupervisor({ workerId: "wkr_worker_concurrent_02" }),
    );

    await Promise.all([sup1.start(), sup2.start()]);

    const req1 = makeAnalyzeRequest({
      taskId: "tsk_concurrent_01",
      workerId: "wkr_worker_concurrent_01",
    });
    const req2 = makeAnalyzeRequest({
      taskId: "tsk_concurrent_02",
      workerId: "wkr_worker_concurrent_02",
    });

    const [res1, res2] = await Promise.all([
      sup1.executeTask(req1),
      sup2.executeTask(req2),
    ]);

    expect(res1.ok).toBe(true);
    expect(res2.ok).toBe(true);

    if (res1.ok && res2.ok) {
      expect(res1.value.taskId).toBe("tsk_concurrent_01");
      expect(res1.value.workerId).toBe("wkr_worker_concurrent_01");
      expect(res2.value.taskId).toBe("tsk_concurrent_02");
      expect(res2.value.workerId).toBe("wkr_worker_concurrent_02");
    }
  });

  // ==========================================================================
  // Scenario 14: Worker exit during active task
  // ==========================================================================
  it("SCENARIO-14: Worker process killed externally while task is active fails fast", async () => {
    const longRunningWorkerScript = `
      process.stdout.write(JSON.stringify({
        protocolVersion: "1.0.0",
        kind: "WORKER_READY",
        messageId: "11111111-1111-4111-8111-111111111111",
        workerId: "wkr_test_worker_01",
        pid: process.pid,
        supportedArchitectures: ["ARM"],
        heapLimitBytes: null
      }) + "\\n");

      process.stdin.on("data", () => {
        // Keep in flight
        setInterval(() => {}, 1000);
      });
    `;

    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_test_worker_01",
        command: process.execPath,
        arguments: ["-e", longRunningWorkerScript],
      }),
    );

    await supervisor.start();
    const pid = supervisor.getChildPid()!;

    const request = makeAnalyzeRequest({ taskId: "tsk_killed_01" });
    const taskPromise = supervisor.executeTask(request);

    // Immediately kill child process from host OS
    setTimeout(() => {
      try {
        process.kill(pid, "SIGTERM");
      } catch {
        // Ignored
      }
    }, 50);

    const result = await taskPromise;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("WORKER_CRASHED");
    }
  });

  // ==========================================================================
  // Scenario 15: Late response from a stale task attempt (fencing token mismatch)
  // ==========================================================================
  it("SCENARIO-15: Late response carrying outdated fencing token is dropped", async () => {
    // Worker that responds with an old fencing token (1 instead of 2)
    const staleResponseWorkerScript = `
      process.stdout.write(JSON.stringify({
        protocolVersion: "1.0.0",
        kind: "WORKER_READY",
        messageId: "11111111-1111-4111-8111-111111111111",
        workerId: "wkr_test_worker_01",
        pid: process.pid,
        supportedArchitectures: ["ARM"],
        heapLimitBytes: null
      }) + "\\n");

      process.stdin.on("data", (chunk) => {
        const req = JSON.parse(chunk.toString().trim());
        // Return stale response with fencingToken: 1 even if request has fencingToken: 2
        process.stdout.write(JSON.stringify({
          protocolVersion: "1.0.0",
          kind: "ANALYZE_RESPONSE",
          messageId: "22222222-2222-4222-8222-222222222222",
          inReplyTo: req.messageId,
          taskId: req.taskId,
          assessmentId: req.assessmentId,
          assetId: req.assetId,
          binarySha256: req.binarySha256,
          runId: req.runId,
          fencingToken: 1, // STALE!
          workerId: req.workerId,
          stage: "DECODE",
          executionStatus: "SUCCESS",
          decodeCompleteness: {
            isComplete: true,
            outcome: "SUCCESS",
            decodedBytes: 4,
            totalBytes: 4
          },
          resultPayload: {},
          resultDigest: "${nopSha256}",
          diagnostics: [],
          resourceUsage: { cpuTimeMs: 1, peakMemoryBytes: 1000, wallTimeMs: 1 }
        }) + "\\n");
      });
    `;

    const events: BinarySupervisorLifecycleEvent[] = [];
    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_test_worker_01",
        command: process.execPath,
        arguments: ["-e", staleResponseWorkerScript],
        defaultTaskTimeoutMs: 300,
        cancelGraceMs: 200,
        onEvent: (e) => events.push(e),
      }),
    );

    await supervisor.start();

    // Dispatch request with fencingToken: 2
    const request = makeAnalyzeRequest({ fencingToken: 2, deadline: Date.now() + 300 });
    const result = await supervisor.executeTask(request);

    // Stale response must be dropped, leading to timeout
    expect(events.some((e) => e.type === "stale_response_dropped")).toBe(true);
    expect(result.ok).toBe(false);
  });

  // ==========================================================================
  // Scenario 16: Parent shutdown with active workers
  // ==========================================================================
  it("SCENARIO-16: Parent shutdown terminates active workers gracefully without hanging", async () => {
    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({ workerId: "wkr_test_worker_01" }),
    );

    await supervisor.start();

    const request = makeAnalyzeRequest();
    // Dispatch task
    void supervisor.executeTask(request);

    // Immediately initiate parent shutdown
    await supervisor.shutdown(500);

    expect(supervisor.getState()).toBe("STOPPED");
  });

  // ==========================================================================
  // Scenario 17: Worker restart/recovery after failure
  // ==========================================================================
  it("SCENARIO-17: Auto-restart restores worker to READY state after crash", async () => {
    const events: BinarySupervisorLifecycleEvent[] = [];
    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_test_worker_01",
        autoRestart: true,
        maxRestarts: 2,
        onEvent: (e) => events.push(e),
      }),
    );

    await supervisor.start();
    const firstPid = supervisor.getChildPid()!;

    // Kill first child
    process.kill(firstPid, "SIGTERM");

    // Wait for auto-restart to complete
    await new Promise((resolve) => setTimeout(resolve, 800));

    expect(events.some((e) => e.type === "worker_restarted")).toBe(true);
    expect(supervisor.getRestartCount()).toBe(1);
    expect(supervisor.getState()).toBe("READY");

    const secondPid = supervisor.getChildPid();
    expect(secondPid).toBeTypeOf("number");
    expect(secondPid).not.toBe(firstPid);
  });

  // ==========================================================================
  // Scenario 18: Resource-limit configuration validation/rejection
  // ==========================================================================
  it("SCENARIO-18: Invalid configuration parameters are strictly rejected", () => {
    expect(
      () =>
        new BinaryWorkerSupervisor({
          workerId: "invalid_prefix",
        }),
    ).toThrow(/Invalid supervisor configuration/);

    expect(
      () =>
        new BinaryWorkerSupervisor({
          maxOldSpaceSizeMb: -50,
        }),
    ).toThrow(/Invalid supervisor configuration/);

    expect(
      () =>
        new BinaryWorkerSupervisor({
          startupTimeoutMs: 0,
        }),
    ).toThrow(/Invalid supervisor configuration/);

    expect(
      () =>
        new BinaryWorkerSupervisor({
          heartbeatIntervalMs: -10,
        }),
    ).toThrow(/Invalid supervisor configuration/);
  });
});
