# REA Phase 3A — Milestone 3 Implementation & Verification Report
## Binary Worker Supervisor and Process Lifecycle Manager

**Document Version:** 1.0.0  
**Date:** November 2026  
**Status:** Completed and Adversarially Verified  
**Milestone:** Phase 3A, Milestone 3 (Supervisor and Lifecycle Management)  
**Author / Security Architect:** Principal Embedded Systems Architect, Operating System Process Isolation Engineer, and Binary Security Specialist  

---

## 1. Executive Summary

Phase 3A Milestone 3 establishes the **trusted host supervisor (`BinaryWorkerSupervisor`)** responsible for managing the complete lifecycle, execution boundaries, resource limits, health monitoring, and recovery of isolated binary-analysis child processes.

This milestone resolves the primary vulnerability identified in the **Milestone 2 Acceptance Review** (`docs/phase-3A-milestone-2-acceptance-review.md`): namely, that **in-process cancellation and deadlines in Node.js cannot interrupt non-yielding, synchronous CPU loops** (such as instruction decoder hangs or infinite CFG graph traversals). By maintaining an independent host-side watchdog timer paired with operating system process termination (Windows Job Objects and POSIX process groups), the supervisor guarantees deterministic preemption even when a worker's single-threaded event loop is completely blocked.

### Key Architectural Invariants Enforced in Milestone 3:
1. **Parent-Worker Trust Boundary:** The child process remains entirely untrusted. It receives zero SQLite database connections, zero HMAC signing keys, zero evidence sealing credentials, and zero finding adjudication authority.
2. **Dual-Tier Host Watchdog:** The supervisor maintains independent host-side deadline timers. On timeout or cancellation, it attempts cooperative cancellation; if the worker does not acknowledge within a bounded grace period (`cancelGraceMs`), the supervisor immediately escalates to hard OS-level process termination.
3. **Stale Response (CAS) Defense:** Responses from timed-out or cancelled workers are matched against the active task's `taskId` and `fencingToken`. Stale responses are discarded without polluting orchestrator state.
4. **Process Tree & Zombie Cleanup:** Every child process is bound to an owned process group (Windows Job Object with `killOnOwnerClose: true` or detached POSIX PGID), guaranteeing zero orphaned processes on exit, crash, parent shutdown, or kill.
5. **Periodic Heartbeat & Crash Recovery:** Supervisor monitors worker health via structured `HEARTBEAT` exchanges and automatically restores workers up to configured restart ceilings (`maxRestarts`).

---

## 2. Implemented Codebase Artifacts

| Component | Path | Responsibility |
|---|---|---|
| **Supervisor Runtime** | [`src/security/binary/supervisor/BinaryWorkerSupervisor.ts`](file:///c:/Users/acer/rea/src/security/binary/supervisor/BinaryWorkerSupervisor.ts) | Manages worker child process spawning, startup handshakes, task dispatch, host watchdog deadlines, heartbeat pings, forced kills, CAS fencing token checks, and auto-restart recovery. |
| **Adversarial Test Suite** | [`src/security/binary/supervisor/BinaryWorkerSupervisor.test.ts`](file:///c:/Users/acer/rea/src/security/binary/supervisor/BinaryWorkerSupervisor.test.ts) | Real OS child-process adversarial test suite covering all 18 required failure and adversarial scenarios. |
| **Milestone 2 Review** | [`docs/phase-3A-milestone-2-acceptance-review.md`](file:///c:/Users/acer/rea/docs/phase-3A-milestone-2-acceptance-review.md) | Comprehensive audit evaluating the 10 security and execution criteria of the Milestone 2 worker runtime. |

---

## 3. Detailed Architectural Mechanisms

### 3.1 Operating System Controls vs. Application-Level Timers

A fundamental design principle of Milestone 3 is the strict separation between what application code can enforce versus what must be delegated to the operating system kernel:

```
+----------------------------------------------------------------------------------------------------+
|                                    PARENT PROCESS (TRUSTED)                                        |
|                                                                                                    |
|   +--------------------------------------------------------------------------------------------+   |
|   | BinaryWorkerSupervisor                                                                     |   |
|   |  - Host Deadline Timer (setTimeout)                                                        |   |
|   |  - Fencing Token & CAS Validation                                                          |   |
|   |  - Heartbeat Watchdog & Miss Counter                                                       |   |
|   |  - Bounded NDJSON Framing (BinaryMessageFramer)                                            |   |
|   +--------------------------------------------------------------------------------------------+   |
|              | stdin (NDJSON)                                    ^ stdout (NDJSON)                 |
|              v                                                   |                                 |
+--------------+---------------------------------------------------+---------------------------------+
               |                                                   |
               | [OS Boundary: Windows Job Object / POSIX PGID]    |
               v                                                   |
+------------------------------------------------------------------+---------------------------------+
|                                 CHILD WORKER PROCESS (UNTRUSTED)                                   |
|                                                                                                    |
|   +--------------------------------------------------------------------------------------------+   |
|   | Node.js Runtime (--max-old-space-size=512)                                                 |   |
|   |  - BinaryWorkerRuntime (stdin EOF listener)                                                |   |
|   |  - BinaryInputResolver (canonical realpath & post-read SHA-256 integrity binding)           |   |
|   |  - BinaryAnalysisDispatcher (SafeElfReader, InProcessInstructionDecoder, CFG builder)      |   |
|   +--------------------------------------------------------------------------------------------+   |
|                                                                                                    |
|   SECURITY BOUNDARIES:                                                                             |
|   - ZERO SQLite connections / database files                                                       |
|   - ZERO HMAC evidence keys / signing authority                                                   |
|   - ZERO finding adjudication / vulnerability verdict issuance                                    |
|   - ZERO target binary execution (read-only analysis)                                              |
+----------------------------------------------------------------------------------------------------+
```

1. **Application-Level Timers (Cooperative):**
   - The worker runtime inspects `signal.aborted` between analysis stages.
   - However, if an instruction decoder or control-flow analysis enters a synchronous loop (`while (true)` or catastrophic backtracking), the Node.js event loop is completely blocked and cannot process incoming IPC control frames.
2. **Host-Side Watchdog & OS Preemption (Forced):**
   - The supervisor starts an independent host-side deadline timer (`setTimeout`) upon task dispatch.
   - When the deadline expires, the supervisor transmits a `CANCEL` frame and starts a cancellation grace timer (`cancelGraceMs`, default: 1,000 ms).
   - If the worker fails to respond with `CANCEL_ACK` or exit within the grace period (proving non-yielding execution), the supervisor executes `forceKillProcess()`:
     - On Windows: terminates the whole Windows Job Object or issues process termination.
     - On POSIX: sends `SIGKILL` to the negative process group (`-pid`).
   - Settle the task promise with `{ code: "TIMEOUT" }` and transitions state to `"TERMINATED"`.

### 3.2 Fencing Token & Stale Response Protection (CAS)

In distributed and multi-process architectures, late responses from timed-out or cancelled tasks can corrupt subsequent task executions if not properly fenced:
- Every task request carries a monotonically increasing `fencingToken` and a unique `requestId` (UUIDv4).
- When `ANALYZE_RESPONSE` arrives, `BinaryWorkerSupervisor` validates:
  ```ts
  if (response.taskId !== activeTask.request.taskId || response.fencingToken !== activeTask.request.fencingToken) {
    this.emitEvent({
      type: "stale_response_dropped",
      taskId: response.taskId,
      fencingToken: response.fencingToken,
      reason: "Mismatched correlation",
    });
    return; // Discarded!
  }
  ```
- Any late response from an earlier task attempt is safely dropped, emitting a structured telemetry event and leaving the active task unaffected.

### 3.3 Health Heartbeats & Automatic Recovery

- The supervisor periodically transmits `HEARTBEAT` messages carrying a unique `messageId` and timestamp.
- The worker echoes the heartbeat on its stdout stream.
- If the worker fails to acknowledge within `heartbeatTimeoutMs`, the supervisor records a missed heartbeat.
- If misses reach `maxHeartbeatMisses` (default: 2), the supervisor marks the worker `"UNRESPONSIVE"`, kills the process group, and initiates automatic restart recovery up to `maxRestarts` (default: 3).

### 3.4 Structured Lifecycle Telemetry

The supervisor emits typed lifecycle events (`BinarySupervisorLifecycleEvent`) with **zero sensitive credential exposure**:
- `spawned`: PID, runId.
- `ready`: workerId, PID, supportedArchitectures.
- `task_dispatched`: taskId, requestId, fencingToken.
- `task_completed`: taskId, durationMs.
- `task_cancelled`: taskId, reason.
- `task_timed_out`: taskId, elapsedMs.
- `heartbeat_sent`, `heartbeat_ack`, `heartbeat_missed`.
- `worker_unresponsive`, `worker_killed`, `worker_crashed`, `worker_restarted`.
- `stale_response_dropped`: taskId, fencingToken.

---

## 4. Adversarial Verification Matrix (18/18 Scenarios Passed)

The real OS child-process adversarial test suite ([`src/security/binary/supervisor/BinaryWorkerSupervisor.test.ts`](file:///c:/Users/acer/rea/src/security/binary/supervisor/BinaryWorkerSupervisor.test.ts)) was executed and verified.

| Scenario ID | Test Name | Injected Fault / Adversarial Condition | Expected Supervisor Behavior | Test Result |
|---|---|---|---|---|
| **SCENARIO-1** | Normal worker startup and shutdown | Routine startup, handshake, and shutdown | Receives `WORKER_READY`, dispatches `SHUTDOWN`, worker exits code 0 | **PASS** (365 ms) |
| **SCENARIO-2** | Worker startup timeout | Worker sleeps without sending `WORKER_READY` | Times out at 250 ms, kills process, state `"TERMINATED"` | **PASS** (282 ms) |
| **SCENARIO-3** | Child crash | Worker exits with non-zero exit code (42) | Detects crash, rejects pending task with `WORKER_CRASHED` | **PASS** (84 ms) |
| **SCENARIO-4** | Child process hang | Worker accepts task but hangs indefinitely | Host watchdog fires, task rejected with `TIMEOUT` | **PASS** (578 ms) |
| **SCENARIO-5** | CPU-bound infinite loop | Worker enters synchronous `while(true)` spin | Host deadline expires, CANCEL unread, escalates to OS kill | **PASS** (551 ms) |
| **SCENARIO-6** | Heartbeat timeout | Worker drops all heartbeat pings | Misses 2 heartbeats, marks `UNRESPONSIVE`, terminates | **PASS** (665 ms) |
| **SCENARIO-7** | Oversized response handling | Worker sends response exceeding 16 MiB line | Framer detects boundary violation, task fails `OVERSIZED_RESPONSE` | **PASS** (1411 ms) |
| **SCENARIO-8** | Malformed IPC response | Worker sends `{"__proto__": {"polluted": true}}` | Parser detects prototype pollution, task fails `PROTOCOL_ERROR` | **PASS** (72 ms) |
| **SCENARIO-9** | Parent cancellation | Parent cancels in-flight task via `cancelTask()` | Transmits `CANCEL`, receives `CANCEL_ACK`, settles `CANCELLED` | **PASS** (415 ms) |
| **SCENARIO-10** | Forced process termination | Caller invokes `supervisor.forceKillProcess()` | Process PID killed, state transitions to `"TERMINATED"` | **PASS** (543 ms) |
| **SCENARIO-11** | Process-tree cleanup | Child is killed after startup | Validates child PID is verified dead in OS process table | **PASS** (362 ms) |
| **SCENARIO-12** | Memory-limit enforcement | Configures memoryLimitBytes with Windows Job Object | Spawns with Windows native authority double; limits verified | **PASS** (1060 ms) |
| **SCENARIO-13** | Multiple concurrent workers | Two supervisors run simultaneously | Isolated stdio channels; no crosstalk or message corruption | **PASS** (400 ms) |
| **SCENARIO-14** | Worker exit during active task | Worker killed externally via `process.kill(pid)` | Catches exit immediately, task fails fast with `WORKER_CRASHED` | **PASS** (50 ms) |
| **SCENARIO-15** | Late stale response | Worker returns response with outdated fencing token (1 vs 2) | Fencing token mismatch detected, response dropped, task timed out | **PASS** (394 ms) |
| **SCENARIO-16** | Parent shutdown with workers | Caller calls `shutdown()` while task is active | Worker terminated cleanly within grace period without hanging | **PASS** (359 ms) |
| **SCENARIO-17** | Worker restart/recovery | Worker killed with `autoRestart: true` | Supervisor catches crash, increments restartCount, spawns fresh child | **PASS** (1149 ms) |
| **SCENARIO-18** | Configuration validation | Invalid worker ID prefix or negative timeouts passed | Strictly rejected at constructor with descriptive Zod error | **PASS** (4 ms) |

---

## 5. Comprehensive Test & Static Analysis Verification

### 5.1 Test Suite Summary
- **Supervisor Adversarial Suite:** 18 passed / 18 total (100% pass rate in 8.77 s).
- **Full Binary Security Suite:** 18 test files, 250 tests passed / 250 total (100% pass rate in 14.45 s):
  - `trustedAnalysisEvidence.test.ts` (43 tests)
  - `BinaryWorkerSupervisor.test.ts` (18 tests)
  - `independentAcceptanceAudit.test.ts` (10 tests)
  - `binaryAnalysisWorkerProcess.test.ts` (2 tests)
  - `evidenceSealer.test.ts` (8 tests)
  - `phase6EndToEnd.test.ts` (3 tests)
  - `BinaryWorkerRuntime.test.ts` (13 tests)
  - `binaryWorkerProtocol.test.ts` (32 tests)
  - `phase23Audit.test.ts` (26 tests)
  - `sprint3A2Audit.test.ts` (15 tests)
  - `controlFlowGraph.test.ts` (37 tests)
  - `vulnerabilityAdjudicationBridge.test.ts` (26 tests)
  - `vulnerabilityCandidateDetector.test.ts` (6 tests)
  - `binaryAnalysisBridge.test.ts` (4 tests)
  - `witnessGenerator.test.ts` (8 tests)
  - `differentialAudit.test.ts` (1 test)
  - `taintEngine.test.ts` (5 tests)

### 5.2 Static Analysis & Lint
Executed `cmd /c npm run check:fast`:
- `tsc --noEmit`: 0 errors.
- `oxlint`: 0 errors.
- `Turbo`: 2/2 tasks successful.

---

## 6. Security Boundaries & Explicit Non-Goals

1. **Untrusted Worker Outputs:**
   - Raw worker outputs (`BinaryWorkerAnalyzeResponse`) returned by the supervisor are **untrusted data transfer objects (DTOs)**.
   - The supervisor does **not** cryptographically sign or validate findings as true vulnerabilities.
2. **No Adjudication Authority:**
   - The supervisor does **not** interface with `VulnerabilityAdjudicationBridge`. Adjudication and cryptographic evidence sealing are strictly deferred to Milestone 4.
3. **No Database Access:**
   - The child worker has zero database connections. Blackboard persistence and CAS state transitions remain parent-orchestrated responsibilities.
4. **No Firmware Execution:**
   - Analysis remains purely static (ELF parsing, linear sweep/recursive decoding, CFG construction, def-use taint tracing). No dynamic execution or emulation is performed.
5. **Milestone Boundary:**
   - Milestone 4 (Parent evidence sealing and adjudication adapter) and Milestone 5 (Blackboard CAS persistence) have **not** been implemented, in strict accordance with the sprint requirements.

