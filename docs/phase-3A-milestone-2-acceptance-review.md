# REA Phase 3A — Milestone 2 Acceptance Review
## Isolated Binary Analysis Child Process Runtime Security & Architectural Evaluation

**Document Version:** 1.0.0  
**Date:** November 2026  
**Auditor / Reviewer:** Principal Embedded Systems Architect, Operating System Process Isolation Engineer, and Binary Security Specialist  
**Target Components:**
- `src/security/binary/worker/BinaryInputResolver.ts`
- `src/security/binary/worker/BinaryAnalysisDispatcher.ts`
- `src/security/binary/worker/BinaryWorkerRuntime.ts`
- `src/composition/binaryAnalysisWorkerProcess.ts`
- `src/security/binary/ipc/binaryWorkerProtocol.ts`
- `src/security/binary/ipc/binaryMessageFramer.ts`

---

## Executive Summary

Phase 3A Milestone 2 establishes an out-of-process execution runtime for untrusted binary security analysis. Before proceeding to Milestone 3 (`BinaryWorkerSupervisor`), an adversarial and structural review was conducted against the Milestone 2 codebase.

The runtime successfully achieves several primary security goals:
1. Complete isolation from parent state (no SQLite database handles, no cryptographic HMAC signing keys, no evidence sealing authority).
2. Strict application-level NDJSON stream framing enforcing a 64 KiB control frame limit and a 16 MiB data frame limit.
3. Canonical path resolution with mandatory post-read cryptographic SHA-256 integrity verification.
4. Deterministic child self-termination upon parent disconnect (`stdin` EOF).

However, critical runtime boundaries remain partial or non-functional without OS-level supervision:
- **Synchronous CPU-intensive loops cannot be interrupted by in-process cancellation or worker deadlines**, because Node.js's single-threaded event loop cannot process incoming IPC control frames while trapped in non-yielding execution.
- **Resource containment (memory ceilings and subprocess creation)** cannot be guaranteed by Node.js application code alone and requires operating-system controls (Windows Job Objects and Linux process groups managed by the supervisor).

The table below summarizes the findings across the 10 required evaluation criteria.

---

## Detailed Evaluation of Mandatory Review Items

| # | Evaluation Criterion | Status | Primary Threat / Observation | Architectural Requirement for Milestone 3 |
|---|---|---|---|---|
| 1 | **Symlink and TOCTOU Races** | **PASS** | Directory symlinks or path swaps could attempt to escape the designated analysis root. | Enforce canonical root validation in supervisor; child post-read digest check prevents payload tampering. |
| 2 | **CPU-Intensive Cancellation** | **FAIL** | Non-yielding synchronous CPU loops block the Node.js event loop, preventing `CANCEL` frames from being processed. | Supervisor must implement external watchdog timer and escalate to forceful OS process termination (SIGKILL / Job Object terminate). |
| 3 | **Execution Deadline Enforcement** | **PARTIAL** | Request-time checks prevent starting expired tasks; in-flight timeouts rely on cooperative stage checkpoints. | Supervisor must track host-side task deadlines and enforce hard preemption. |
| 4 | **Bounded Buffering (Input/Output)** | **PASS** | Oversized JSON payloads or unbounded streams could cause parent/child heap exhaustion. | Retain bounded `BinaryMessageFramer` ceilings (64 KiB control, 16 MiB data). |
| 5 | **Real Analysis Engine Invocation** | **PASS** | Stubs or simulated providers could misrepresent analysis completeness. | Real engines (`SafeElfReader`, `InProcessInstructionDecoder`, `ControlFlowGraphBuilder`) are properly wired. |
| 6 | **Deterministic Child Shutdown** | **PASS** | Residual background work or unclosed handles could cause child processes to hang indefinitely. | Graceful `SHUTDOWN` -> `SHUTDOWN_ACK` handshake tested; supervisor terminates process group on shutdown. |
| 7 | **Stream Drainage Prior to Exit** | **PASS** | Premature `process.exit()` calls can truncate pending stdout/stderr buffers in the OS pipe. | Stream writes are completed and awaited before process termination. |
| 8 | **Filesystem Privilege Confinement** | **PARTIAL** | Child executes under the parent user account without OS kernel isolation or chroot/sandbox boundaries. | Use isolated temporary `PrivateRuntimeRoot` per worker run; pass inputs via inline buffer where possible. |
| 9 | **Subprocess Spawning Prevention** | **PARTIAL** | Compromised worker or native library could spawn uncontrolled child processes or daemons. | Enforce process group tracking (Windows Job Object `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and POSIX PGID cleanup). |
| 10 | **Parent Disconnect Termination** | **PASS** | Orphaned worker processes could continue consuming CPU/RAM after parent crashes or restarts. | Child registers `stdin.on("end")` and terminates immediately with exit code 0. |

---

## Detailed Audit Findings

### 1. Symlink and TOCTOU Races
- **Code Locations:** `src/security/binary/worker/BinaryInputResolver.ts` (lines 101–168), `src/security/binary/ipc/binaryWorkerProtocol.ts` (lines 109–146).
- **Audit Findings:**
  1. `validateBinaryInputReference` enforces that input paths must be absolute and contain no relative traversal segments (`..`).
  2. `BinaryInputResolver.resolveFilePath()` resolves both `allowedRoot` and the requested `ref.path` using `fs.realpath()`. This expands any symlinks prior to path comparison.
  3. The relative offset between `canonicalRoot` and `canonicalPath` is validated to ensure the real target resides strictly inside the canonical root.
  4. **TOCTOU Defense:** Between the `realpath` check and `readFile`, a concurrent adversary could theoretically swap the target file. However, `BinaryInputResolver` computes `crypto.createHash("sha256").update(buffer).digest("hex")` directly on the loaded buffer in memory and checks equality against `ref.expected_sha256`. If the content does not match the parent's declared digest, the resolver returns `DIGEST_MISMATCH` and fails closed.
- **Verdict:** **PASS**

### 2. CPU-Intensive Cancellation
- **Code Locations:** `src/security/binary/worker/BinaryWorkerRuntime.ts` (lines 280–310), `src/security/binary/worker/BinaryAnalysisDispatcher.ts` (lines 78–125).
- **Audit Findings:**
  1. `BinaryWorkerRuntime` listens for `CANCEL` messages on `stdin` and triggers `this.activeAbortController?.abort()`.
  2. `BinaryAnalysisDispatcher` checks `signal?.throwIfAborted()` between sequential stages (e.g. between decoding and CFG construction).
  3. **Vulnerability:** Node.js runs a single-threaded event loop. If a worker stage encounters a pathological input causing a synchronous infinite loop (`while (true) {}`) or deeply recursive execution in an instruction decoder or graph builder:
     - The event loop cannot tick.
     - Node.js cannot read chunks from `process.stdin`.
     - The `CANCEL` frame remains buffered in the OS socket pipe and is never deserialized.
     - `AbortSignal` is never triggered.
- **Verdict:** **FAIL (for in-process cancellation)**. In-process cancellation is purely cooperative.
- **Milestone 3 Mandate:** Preempting CPU-bound hangs strictly requires host-side OS process supervision. The `BinaryWorkerSupervisor` must maintain an external watchdog timer and issue an OS-level termination (`process.kill("SIGKILL")` or Windows Job Object `TerminateJobObject`) when a worker fails to acknowledge cancellation within a bounded grace period (`cancelGraceMs`).

### 3. Execution Deadline Enforcement
- **Code Locations:** `src/security/binary/worker/BinaryWorkerRuntime.ts` (lines 205–218).
- **Audit Findings:**
  1. Upon receiving `ANALYZE_REQUEST`, the runtime verifies `if (request.deadline <= Date.now())` and returns a `TIMEOUT` error immediately.
  2. However, for in-flight tasks, deadline enforcement relies on the cooperative checks inside `dispatcher.dispatch()`.
  3. If a task exceeds its deadline while executing a long-running native or synchronous JavaScript operation, the child will not interrupt itself.
- **Verdict:** **PARTIAL**.
- **Milestone 3 Mandate:** The supervisor must track the task deadline host-side and initiate cancellation/termination when `Date.now() >= deadline`.

### 4. Bounded Input and Output Buffering
- **Code Locations:** `src/security/binary/ipc/binaryMessageFramer.ts` (lines 20–120), `src/security/binary/ipc/binaryWorkerProtocol.ts` (lines 12–26).
- **Audit Findings:**
  1. Control frames are restricted to 64 KiB (`BINARY_IPC_CONTROL_FRAME_MAX_BYTES`).
  2. Data frames are restricted to 16 MiB (`BINARY_IPC_DATA_FRAME_MAX_BYTES`).
  3. The framing buffer enforces a hard ceiling of 16.001 MiB (`BINARY_IPC_MAX_PENDING_BYTES`). If incoming stream data does not contain a newline delimiter before reaching this limit, a `RangeError` is thrown, discarding the buffer and failing closed.
  4. Queued messages are bounded, preventing memory accumulation during backpressure.
- **Verdict:** **PASS**.

### 5. Real Analysis Engine Invocation
- **Code Locations:** `src/security/binary/worker/BinaryAnalysisDispatcher.ts` (lines 1–250).
- **Audit Findings:**
  1. The dispatcher instantiates and executes `SafeElfReader` for ELF validation and section header parsing.
  2. It invokes `InProcessInstructionDecoder` to disassemble machine code into typed instruction streams (`rawInstructionSchema`).
  3. It invokes `ControlFlowGraphBuilder` to construct basic blocks, control-flow edges, and calculate CFG hash representations.
  4. There are no placeholder stubs or synthetic bypasses in the execution path.
- **Verdict:** **PASS**.

### 6. Deterministic Child Process Shutdown
- **Code Locations:** `src/security/binary/worker/BinaryWorkerRuntime.ts` (lines 320–355), `src/composition/binaryAnalysisWorkerProcess.ts` (lines 14–23).
- **Audit Findings:**
  1. On receipt of a `SHUTDOWN` frame, the worker sets its internal state to `SHUTTING_DOWN`.
  2. It responds with a `SHUTDOWN_ACK` frame over stdout and flushes the stream.
  3. The runtime loop terminates, resolving the exit promise, and `binaryAnalysisWorkerProcess.ts` calls `process.exit(0)`.
  4. Integration tests confirm that worker processes exit cleanly within 500 ms without hanging.
- **Verdict:** **PASS**.

### 7. Stream Drainage Prior to Process Exit
- **Code Locations:** `src/security/binary/worker/BinaryWorkerRuntime.ts` (lines 340–355, 490–510).
- **Audit Findings:**
  1. All frame transmissions await stream drainage callbacks before completing the response promise.
  2. `SHUTDOWN_ACK` is transmitted with an explicit callback wait before closing the output stream.
  3. `process.exit(0)` is invoked only after `runtime.start()` resolves asynchronously, ensuring pending microtasks and stream flushes finish.
- **Verdict:** **PASS**.

### 8. Filesystem Privilege Confinement
- **Code Locations:** Ambient process environment in `src/composition/binaryAnalysisWorkerProcess.ts`.
- **Audit Findings:**
  1. The child process runs under the ambient credentials and permissions of the parent Node.js process.
  2. While `BinaryInputResolver` logically prevents accessing files outside `allowedRoot`, a compromised worker executing native shellcode or exploit payloads possesses the ambient user account permissions.
  3. OS-level sandboxing (e.g., Linux user namespaces/seccomp or Windows AppContainer) is not implemented at the worker layer.
- **Verdict:** **PARTIAL**.
- **Milestone 3 Mandate:** The supervisor must pass `allowedRoot` pointing to a unique, isolated `PrivateRuntimeRoot` per worker run, and avoid passing sensitive directory paths. Target binaries should be supplied via `inline_buffer` where feasible.

### 9. Subprocess Spawning Prevention and Control
- **Code Locations:** Node.js runtime process environment.
- **Audit Findings:**
  1. The worker application code does not import or call `child_process`.
  2. However, the child process is not prevented by Node.js from creating child processes if native code or a dependency attempts it.
  3. If a child worker spawns grandchildren, killing the child PID directly could leave orphaned zombie processes.
- **Verdict:** **PARTIAL**.
- **Milestone 3 Mandate:** The supervisor must track the entire process tree using REA's `ProcessOwnership` infrastructure:
  - On Windows: attach the worker process to a native Windows Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
  - On Linux/macOS: spawn with `detached: true` and terminate the entire process group (PGID) on cleanup.

### 10. Parent Disconnect Termination
- **Code Locations:** `src/security/binary/worker/BinaryWorkerRuntime.ts` (lines 105–118).
- **Audit Findings:**
  1. The runtime attaches a listener to `inputStream.on("end", ...)`.
  2. When the parent process terminates, crashes, or closes `stdin`, the child receives EOF immediately.
  3. The runtime logs a parent disconnect message to stderr and invokes `this.terminate("parent_disconnected")`, exiting cleanly with code 0.
  4. Tested and confirmed in both unit and real-process integration tests.
- **Verdict:** **PASS**.

---

## Conclusion & Action Plan for Milestone 3

Milestone 2 provides a solid, strictly isolated application runtime, but confirms that **application-level code cannot protect against non-yielding CPU loops, unbounded host memory allocation, or orphan process trees**.

### Core Requirements for `BinaryWorkerSupervisor` (Milestone 3):
1. **OS-Level Process Group Management:**
   - Integrate `spawnOwnedProviderProcess` and `WindowsOwnedProcess` to assign every child worker to a native Windows Job Object (`killOnOwnerClose: true`) or POSIX detached PGID.
2. **Dual-Tier Host Watchdog:**
   - Maintain an independent host-side deadline timer.
   - On timeout/cancellation: send a cooperative `CANCEL` frame over `stdin`.
   - If the worker does not terminate or acknowledge within `cancelGraceMs` (500–1000 ms), execute an immediate, forceful OS process kill to reclaim CPU and memory.
3. **Heartbeat Monitoring:**
   - Periodically exchange `HEARTBEAT` messages; mark workers unresponsive if heartbeats are missed.
4. **Fencing Token & CAS Protection:**
   - Track active task `fencingToken` and `taskId`; silently drop late/stale responses from previous task attempts.
5. **Structured Telemetry:**
   - Emit detailed lifecycle events for observability with zero credential leakage.

Milestone 2 is hereby **ACCEPTED WITH CONDITIONS**, authorizing the implementation of Milestone 3.

