# REA Phase 3A — Milestone 2: Isolated Binary Analysis Child Process Runtime Report
## Architecture, Process Isolation, IPC Integration, and Empirical Verification

**Platform:** Reverse Engineering Assistant (REA)  
**Component:** Embedded Binary Security Investigation Pipeline — Multi-Process Isolation  
**Phase:** Phase 3A (Multi-Process Binary Analysis Architecture)  
**Milestone:** Milestone 2 — Isolated Binary Analysis Child Process Runtime  
**Status:** COMPLETE (15/15 Worker Tests Passing, 232/232 Binary Suite Tests Passing, Static Typecheck & Lint Clean)  
**Date:** November 2026  

---

## 1. Executive Summary & Milestone Scope

In accordance with the authoritative Phase 3A architecture blueprint ([`docs/phase-3A-multiprocess-architecture.md`](file:///c:/Users/acer/rea/docs/phase-3A-multiprocess-architecture.md)), **Milestone 2** implements an isolated binary-analysis child process runtime.

This milestone establishes the child process runtime that executes within an isolated OS process, receives bounded task requests over standard input/output pipes via the Newline-Delimited JSON (NDJSON) framing substrate established in Milestone 1, resolves binary inputs through scoped, read-only references, dispatches stage analysis (disassembly, control-flow graph construction, reachability analysis, taint propagation, witness synthesis), and yields strictly untrusted raw Data Transfer Objects (DTOs) back to the parent.

### Strict Scope Enforcement
- **Implemented in Milestone 2:**
  1. Child process bootstrap and CLI entrypoint ([`src/composition/binaryAnalysisWorkerProcess.ts`](file:///c:/Users/acer/rea/src/composition/binaryAnalysisWorkerProcess.ts)).
  2. Protocol initialization with `WORKER_READY` handshake.
  3. Bounded input resolution with path traversal and allowed root containment defenses ([`src/security/binary/worker/BinaryInputResolver.ts`](file:///c:/Users/acer/rea/src/security/binary/worker/BinaryInputResolver.ts)).
  4. In-worker static analysis dispatcher ([`src/security/binary/worker/BinaryAnalysisDispatcher.ts`](file:///c:/Users/acer/rea/src/security/binary/worker/BinaryAnalysisDispatcher.ts)).
  5. Isolated child process runtime state machine and stream controller ([`src/security/binary/worker/BinaryWorkerRuntime.ts`](file:///c:/Users/acer/rea/src/security/binary/worker/BinaryWorkerRuntime.ts)).
  6. Comprehensive unit test suite (13 tests) and real child-process integration test suite (2 tests).
- **Explicitly Deferred (Strictly Preserved for Subsequent Milestones):**
  - **Milestone 3:** `BinaryWorkerSupervisor` (process tree supervision, Job Object/PGID tracking, SIGTERM/SIGKILL escalation, heartbeat watchdog).
  - **Milestone 4:** `ParentEvidenceValidator` and `BinaryAnalysisWorkerBridge` (parent-side HMAC signing and adjudication bridge).
  - **Milestone 5:** Production `BinaryAnalysisWorker` delegation and SQLite blackboard CAS task lease persistence.
  - **Milestone 6:** Adversarial multi-process verification.

---

## 2. Exact Files Created and Modified

| File Path | Status | Purpose |
| :--- | :--- | :--- |
| [`src/security/binary/worker/BinaryInputResolver.ts`](file:///c:/Users/acer/rea/src/security/binary/worker/BinaryInputResolver.ts) | Created | Scoped resolution of parent-issued binary references; traversal defense; digest verification; read-only guarantees. |
| [`src/security/binary/worker/BinaryAnalysisDispatcher.ts`](file:///c:/Users/acer/rea/src/security/binary/worker/BinaryAnalysisDispatcher.ts) | Created | Dispatches analysis stages (`PARSE`, `DECODE`, `CFG`, `REACHABILITY`, `TAINT`, `WITNESS`, `ALL`) into untrusted DTOs; computes deterministic canonical SHA-256 `resultDigest`. |
| [`src/security/binary/worker/BinaryWorkerRuntime.ts`](file:///c:/Users/acer/rea/src/security/binary/worker/BinaryWorkerRuntime.ts) | Created | Child process runtime loop; lifecycle management; request validation; deadline enforcement; stderr diagnostic isolation; graceful shutdown. |
| [`src/composition/binaryAnalysisWorkerProcess.ts`](file:///c:/Users/acer/rea/src/composition/binaryAnalysisWorkerProcess.ts) | Created | Standalone executable child process entrypoint executed by Node.js. |
| [`src/security/binary/worker/BinaryWorkerRuntime.test.ts`](file:///c:/Users/acer/rea/src/security/binary/worker/BinaryWorkerRuntime.test.ts) | Created | 13 focused unit tests covering stream framing, validation, stage execution, deadlines, cancellations, and error sanitization. |
| [`src/security/binary/worker/binaryAnalysisWorkerProcess.test.ts`](file:///c:/Users/acer/rea/src/security/binary/worker/binaryAnalysisWorkerProcess.test.ts) | Created | Real OS subprocess integration tests executing Node.js against `binaryAnalysisWorkerProcess.ts` with stdio pipes. |
| [`package.json`](file:///c:/Users/acer/rea/package.json) | Modified | Added `"#binary-analysis-worker"` export mapping for child process runtime resolution. |
| [`src/security/binary/ipc/binaryWorkerProtocol.ts`](file:///c:/Users/acer/rea/src/security/binary/ipc/binaryWorkerProtocol.ts) | Modified | Exported inferred DTO and lifecycle types; strengthened path traversal check using `path.relative`. |

---

## 3. Architecture & Security Boundaries

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 PARENT PROCESS (Trusted)                               │
│  - SQLite Blackboard Database               - Secure Keyring & HMAC Secrets            │
│  - Evidence Sealing Authority               - Vulnerability Adjudication Engine        │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ stdio pipes (NDJSON Framing)
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              CHILD PROCESS RUNTIME (Untrusted)                         │
│                                                                                        │
│   src/composition/binaryAnalysisWorkerProcess.ts                                       │
│       │                                                                                │
│       ├── stdin ──► BinaryMessageFramer ──► Request Validation (binaryWorkerProtocol)  │
│       │                                          │                                     │
│       │                                          ▼                                     │
│       │                               BinaryInputResolver                              │
│       │                                (Path Traversal & Allowed Root Checks)          │
│       │                                          │                                     │
│       │                                          ▼                                     │
│       │                               BinaryAnalysisDispatcher                         │
│       │                                (Pure Static Execution: No Execution Authority) │
│       │                                          │                                     │
│       ├── stdout ◄── Framer.serialize() ◄────────┴─ Untrusted Raw DTOs                 │
│       │                                                                                │
│       └── stderr ◄── Controlled Diagnostic Telemetry (Zero Debug Noise on stdout)      │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1. Zero Trust Environment
The child worker process operates under explicit zero-trust constraints:
1. **No Database Access:** The child runtime imports zero SQLite modules, repositories, or blackboard entities.
2. **No Cryptographic Signing Keys:** The child runtime imports zero keyring managers or HMAC keys; it cannot sign evidence.
3. **No Finding Adjudication Authority:** The worker outputs raw syntactic and semantic graphs. It is structurally prohibited from setting candidate lifecycle states or issuing `VERIFIED` / `FALSE_POSITIVE` verdicts.
4. **No Target Execution:** Binary analysis is 100% static parsing. The target binary is never marked executable (`chmod +x`), spawned, or emulated dynamically.
5. **Stdio Protocol Purity:** Standard output is strictly reserved for newline-delimited JSON frames matching `binaryWorkerIpcMessageSchema`. Diagnostic logs and stack traces are directed exclusively to standard error.

### 3.2. Scoped Binary Input Resolution (`BinaryInputResolver`)
The child rejects arbitrary filesystem paths:
- **Reference-Based Scoping:** Files must be explicitly referenced by a parent-issued `BinaryInputReference`.
- **Traversal Sequences:** Any raw or normalized path containing `..` is rejected immediately with `PATH_TRAVERSAL`.
- **Allowed Sandbox Root Enforcement:** If `allowedRoot` is configured, `BinaryInputResolver` computes `path.relative(rootNormalized, targetNormalized)`. If the relative path begins with `..` or is absolute (e.g. escaping drive boundaries on Windows), resolution fails closed.
- **Cryptographic Digest Binding:** The SHA-256 of read bytes is computed and compared against `ref.expected_sha256`. Any mismatch aborts analysis immediately.

### 3.3. Stage Analysis Dispatcher (`BinaryAnalysisDispatcher`)
Translates valid analysis requests into strictly bounded analysis operations:
- `DECODE`: Invokes `InProcessInstructionDecoder` to disassemble bytes starting from the target entry point.
- `CFG`: Invokes `ControlFlowGraphBuilder` to construct basic blocks and control-flow edges.
- `REACHABILITY`: Identifies execution paths from entry points to security-sensitive sinks.
- `TAINT`: Tracks source-to-sink data flow and records sanitizer dominance.
- `WITNESS`: Synthesizes input constraints and preconditions.
- **Deterministic Digesting:** Canonicalizes output payloads using RFC 8785 (`canonicalize`) and computes a SHA-256 `resultDigest`.

### 3.4. Lifecycle and Protocol State Machine (`BinaryWorkerRuntime`)
- `UNINITIALIZED`: Initial constructor state.
- `READY`: Emits `WORKER_READY` frame with PID, supported architectures, and V8 heap limits.
- `PROCESSING`: Active analysis task executing under `AbortController` and deadline constraints.
- `SHUTTING_DOWN`: Responds with `SHUTDOWN_ACK`, cleans up stream listeners, and terminates.
- `TERMINATED`: Final state; stream pipes destroyed and process exits with code 0.
- **Deterministic Disconnect Termination:** When parent closes `stdin` (EOF), the child detects disconnection and exits immediately with code 0 without hanging.

---

## 4. Test Suite Execution and Verification Results

The implementation was validated through two test suites covering unit-level stream interactions and real multi-process child execution.

### 4.1. Unit Test Suite: `BinaryWorkerRuntime.test.ts` (13/13 Passing)
```
 ✓  adapters  src/security/binary/worker/BinaryWorkerRuntime.test.ts (13 tests) 34ms
   ✓ TEST-1: Bootstraps runtime, emits WORKER_READY frame, and enters READY state
   ✓ TEST-2: Processes valid ANALYZE_REQUEST with inline buffer for DECODE stage
   ✓ TEST-3: Processes valid ANALYZE_REQUEST for CFG, REACHABILITY, TAINT, and WITNESS stages
   ✓ TEST-4: Rejects request with worker ID mismatch
   ✓ TEST-5: Rejects request with expired deadline before start
   ✓ TEST-6: Rejects binary input with SHA-256 digest mismatch
   ✓ TEST-7: Rejects file_path binary input with path traversal or root escape
   ✓ TEST-8: Handles HEARTBEAT message and reflects active task state
   ✓ TEST-9: Handles CANCEL message and responds with CANCEL_ACK
   ✓ TEST-10: Handles SHUTDOWN message with SHUTDOWN_ACK and clean state transition
   ✓ TEST-11: Detects parent disconnect on stdin EOF and terminates gracefully
   ✓ TEST-12: Error message sanitation removes filesystem paths and stack traces
   ✓ TEST-13: Verifies child runtime does not import or hold database or evidence signing authority
```

### 4.2. Child Process Integration Suite: `binaryAnalysisWorkerProcess.test.ts` (2/2 Passing)
Exercises the real Node.js child process (`node --import tsx src/composition/binaryAnalysisWorkerProcess.ts`):
```
 ✓  adapters  src/security/binary/worker/binaryAnalysisWorkerProcess.test.ts (2 tests) 526ms
   ✓ REAL-CHILD-1: Spawns binaryAnalysisWorkerProcess, completes handshake, processes requests, and shuts down cleanly
   ✓ REAL-CHILD-2: Child terminates deterministically on parent stdin EOF without hanging
```

### 4.3. Full Binary Security Regression Suite (17 Files, 232 Tests Passing)
```
 Test Files  17 passed (17)
      Tests  232 passed (232)
   Start at  18:29:43
   Duration  7.15s (tests 74%, import 14%, transform 11%, worker 2%)
```
Zero regressions across all existing binary analysis suites (`independentAcceptanceAudit`, `differentialAudit`, `phase23Audit`, `controlFlowGraph`, `trustedAnalysisEvidence`, `evidenceSealer`, `vulnerabilityAdjudicationBridge`, `taintEngine`, `witnessGenerator`).

### 4.4. Static Analysis & Lint Gate
```
> rea-agents@6.7.0 check:fast
> turbo run typecheck lint --output-logs=errors-only

 Tasks:    2 successful, 2 total
 Cached:   0 cached, 2 total
   Time:    16.815s
```
Zero TypeScript compiler errors across all files (`exactOptionalPropertyTypes: true` compliant) and zero oxlint errors across 3,972 files.

---

## 5. Failed Tests and Technical Resolutions

During iterative development, the following issues were encountered and resolved:

| # | Root Cause | Impact | Technical Resolution |
| :--- | :--- | :--- | :--- |
| **1** | Windows `path.normalize("/sandbox/../../etc/shadow")` collapsed to `\etc\shadow`, bypassing `normalized.includes("..")`. | TEST-21 failed to reject traversal. | Updated `validateBinaryInputReference` to inspect `rawPath.includes("..")` and verify `path.relative(root, target)` boundary containment. |
| **2** | Test sent stage name `"DECODER"` instead of schema enum `"DECODE"`. | Schema validation failed (`Invalid option: expected one of "PARSE"\|"DECODE"...`). | Corrected test requests and added dispatch handling for all stages (`PARSE`, `DECODE`, `CFG`, `REACHABILITY`, `TAINT`, `WITNESS`, `ALL`). |
| **3** | `runtime.state = "READY"` occurred after awaiting `sendReadyFrame()`. | Race condition where `readyPromise` resolved before `state` updated. | Set `this.state = "READY"` immediately prior to writing `WORKER_READY` frame. |
| **4** | `Instruction` interface in `cfg/types.ts` uses `rawBytes: Uint8Array`, not `bytes: Buffer`. | `TypeError: The first argument must be of type string or Buffer... Received undefined`. | Updated `BinaryAnalysisDispatcher` to read `inst.rawBytes` and instantiate `new Uint8Array(Buffer.from(rawBytesHex, "hex"))`. |
| **5** | `BasicBlock` interface defines `predecessorIds: readonly string[]`, not `predecessors`. | `TypeError: b.predecessors is not iterable`. | Updated CFG mapping to read `b.predecessorIds`, `b.successorIds`, and `b.terminatorType`. |
| **6** | `exactOptionalPropertyTypes: true` flagged `workerId?: string` with `undefined`. | `TS2379: Argument of type '{ workerId: string \| undefined }' is not assignable`. | Explicitly declared `?: string \| undefined` across all optional option types. |
| **7** | Child process did not exit on graceful `SHUTDOWN` because `stdin` handle remained active in libuv. | Integration test timed out after 30 seconds. | Added `process.exit(0)` on `runtime.start()` completion in `binaryAnalysisWorkerProcess.ts` and paused/destroyed `inputStream` in `runtime.terminate()`. |

---

## 6. Known Limitations & Deferred Features

1. **Uncooperative Process Termination:**
   - *Limitation:* If child native code crashes or hangs in an infinite loop, the child runtime cannot self-terminate.
   - *Resolution Plan:* **Milestone 3** implements `BinaryWorkerSupervisor` with OS-level `SIGKILL` escalation, Job Object kill-on-close, and timeout monitoring.
2. **OS-Level Hard Memory Ceilings:**
   - *Limitation:* Current memory limits rely on Node.js V8 heap statistics and voluntary memory monitoring.
   - *Resolution Plan:* **Milestone 3** enforces OS-level memory bounds via Windows Job Objects (`JobObjectExtendedLimitInformation`) and Linux `prlimit --as`.
3. **Blackboard Database Task Updating:**
   - *Limitation:* The child runtime intentionally has no database access and cannot update task states or leases.
   - *Resolution Plan:* **Milestone 4 & 5** implement parent-side task lease verification, CAS fencing updates, and evidence sealing.

---

## 7. Confirmation of Milestone Boundary Compliance

- [x] No `BinaryWorkerSupervisor` or process manager was implemented ahead of schedule.
- [x] No parent evidence signing or adjudication integration was implemented.
- [x] No blackboard or SQLite database access was granted to the worker.
- [x] No firmware execution occurs.
- [x] Milestone 2 is complete, verified, and ready for review prior to commencing Milestone 3.

