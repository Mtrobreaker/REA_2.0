# REA Phase 3A: Multi-Process Binary Analysis Architecture & Implementation Plan

**Document Reference:** `docs/phase-3A-multiprocess-architecture.md`  
**Classification:** Systems Architecture, Security Architecture, Process Isolation, Cryptographic Evidence Pipeline  
**Target:** REA Embedded Firmware Security Investigation Platform  
**Author:** Principal Systems Architect, Embedded Firmware Security Engineer, Node.js Runtime Engineer  
**Date:** November 2026  
**Status:** Approved for Implementation Planning  

---

## 1. Executive Summary & Objective

In Sprint 3B and Sprint 3B.1, REA established a mathematically proven, cryptographically sealed trust boundary for intermediate binary analysis evidence. All 196 binary security tests passed, constant-time HMAC verification was enforced, single-use witness consumption was guaranteed, and production authentication bypasses were eradicated.

However, the entire analysis pipeline currently executes within a **single Node.js process**:
1. **No Memory Isolation:** Parsing untrusted ELF binaries, decoding arbitrary machine code, and performing complex reachability/taint graphs occurs in the same V8 isolate and operating system process that hosts the authoritative SQLite database (`blackboard.db`), the cryptographic key material (`KeyringManager`), and orchestration logic.
2. **Crash & Resource Contagion:** A native crash (e.g., segmentation fault in disassembler bindings), an allocation bomb (memory exhaustion), or an infinite loop in CFG analysis immediately kills the parent orchestrator, terminates all concurrent investigation tasks, and risks database corruption.
3. **Absence of Host-Level Trust Boundaries:** While ECMAScript private fields (`#field`) and unexported Symbols prevent prototype reflection in JavaScript, they **do not provide OS-level process isolation**. A compromised native provider or memory-corrupted worker could read process memory or compromise other assessments.
4. **Instruction Decoding & Taint Coverage Gaps:** Previous differential evaluations against LLVM objdump highlighted x86-64 coverage limitations (O0: ~3.2%, O2: ~2.4%), which cause decode outcomes to degrade to `PARTIAL`, forcing reachability to `INCONCLUSIVE`.

**Objective of Phase 3A:**  
Design and plan the transition of REA's binary analysis pipeline to a **multi-process architecture with strict IPC boundaries**. The architecture will isolate untrusted binary execution and intermediate graph algorithms into dedicated child worker processes, while centralizing all cryptographic signing authority, database mutations, and vulnerability adjudication within the trusted parent orchestrator.

---

## 2. Current Architecture Inspection & Discrepancies

### 2.1 Code Inspected
The current codebase was inspected across nine core architectural domains:
1. **Evidence & Cryptography:** [`TrustedAnalysisEvidence.ts`](file:///c:/Users/acer/rea/src/security/binary/evidence/TrustedAnalysisEvidence.ts), [`types.ts`](file:///c:/Users/acer/rea/src/security/binary/evidence/types.ts), [`secureKeyring.ts`](file:///c:/Users/acer/rea/src/security/packboard/secureKeyring.js).
2. **Adjudication Engine:** [`VulnerabilityAdjudicationBridge.ts`](file:///c:/Users/acer/rea/src/security/binary/VulnerabilityAdjudicationBridge.ts), [`MultiStageAdjudicator.ts`](file:///c:/Users/acer/rea/src/application/security/adjudicate/MultiStageAdjudicator.ts).
3. **Binary Analysis Pipeline:** [`BinaryAnalysisBridge.ts`](file:///c:/Users/acer/rea/src/security/binary/BinaryAnalysisBridge.ts), [`VulnerabilityCandidateDetector.ts`](file:///c:/Users/acer/rea/src/security/binary/VulnerabilityCandidateDetector.ts), [`InstructionDecoder.ts`](file:///c:/Users/acer/rea/src/security/binary/cfg/InstructionDecoder.ts), [`ControlFlowGraphBuilder.ts`](file:///c:/Users/acer/rea/src/security/binary/cfg/ControlFlowGraphBuilder.ts), [`ReachabilityAnalyzer.ts`](file:///c:/Users/acer/rea/src/security/binary/cfg/ReachabilityAnalyzer.ts), [`TaintEngine.ts`](file:///c:/Users/acer/rea/src/security/binary/taint/TaintEngine.ts), [`WitnessValidator.ts`](file:///c:/Users/acer/rea/src/security/binary/witness/WitnessValidator.ts).
4. **Worker & Orchestration:** [`BinaryAnalysisWorker.ts`](file:///c:/Users/acer/rea/src/application/security/workers/BinaryAnalysisWorker.ts), [`ChiefSecurityOrchestrator.ts`](file:///c:/Users/acer/rea/src/application/security/coordinator/ChiefSecurityOrchestrator.ts), [`AgentWorker.ts`](file:///c:/Users/acer/rea/src/application/security/coordinator/AgentWorker.ts).
5. **Context & Projection:** [`ContextProjector.ts`](file:///c:/Users/acer/rea/src/application/security/blackboard/ContextProjector.ts).
6. **Blackboard Database:** [`BlackboardSchema.ts`](file:///c:/Users/acer/rea/src/security/blackboard/BlackboardSchema.ts), [`SqliteBlackboardStorage.ts`](file:///c:/Users/acer/rea/src/security/blackboard/SqliteBlackboardStorage.ts).
7. **Process Management Foundation:** [`ProcessOwnership.ts`](file:///c:/Users/acer/rea/src/process/ProcessOwnership.ts), [`ProviderProcess.ts`](file:///c:/Users/acer/rea/src/process/ProviderProcess.js), [`PrivateRuntimeRoot.ts`](file:///c:/Users/acer/rea/src/process/PrivateRuntimeRoot.ts), [`LinuxResourceLimits.ts`](file:///c:/Users/acer/rea/src/process/LinuxResourceLimits.ts), [`JavaScriptWorkerMemoryLimit.ts`](file:///c:/Users/acer/rea/src/process/JavaScriptWorkerMemoryLimit.ts).
8. **Precedent IPC Implementations:** [`JavaScriptAnalysisWorker.ts`](file:///c:/Users/acer/rea/src/javascript/analysis/JavaScriptAnalysisWorker.ts), [`JavaScriptAnalysisWorkerProtocol.ts`](file:///c:/Users/acer/rea/src/javascript/analysis/JavaScriptAnalysisWorkerProtocol.ts), [`javascriptAnalysisWorkerProcess.ts`](file:///c:/Users/acer/rea/src/composition/javascriptAnalysisWorkerProcess.ts).
9. **Benchmark & Tests:** [`BenchmarkRunner.ts`](file:///c:/Users/acer/rea/src/security/binary/benchmark/BenchmarkRunner.ts), [`independentAcceptanceAudit.test.ts`](file:///c:/Users/acer/rea/src/security/binary/evidence/independentAcceptanceAudit.test.ts).

### 2.2 Existing Implementation vs. Historical Reports (Discrepancies Identified)
- **Discrepancy 1 (Benchmark vs. Worker Pipeline):** In `BenchmarkRunner.ts`, the full 5-stage pipeline (`Decoder` &rarr; `CFG` &rarr; `Reachability` &rarr; `Taint` &rarr; `Witness` &rarr; `Adjudication`) is implemented and verified. However, in `BinaryAnalysisWorker.ts`, only shallow ELF parsing (`BinaryAnalysisBridge`) and heuristic candidate detection (`VulnerabilityCandidateDetector`) are executed; deep instruction decoding, reachability, and witness validation are not yet wired into the production blackboard task loop.
- **Discrepancy 2 (In-Process Adjudication & DB Mutation):** `BinaryAnalysisWorker.ts` directly calls `this.adjudicator.adjudicateCandidate` and writes directly to `this.blackboard.findings.create` and `this.blackboard.observations.record`. The worker is not isolated from the database.
- **Discrepancy 3 (Single-Process Fallacy):** While Sprint 3B reports emphasized cryptographic sealing, the current `AgentWorker` and `BinaryAnalysisWorker` instantiate all parsers in the same Node.js event loop as the orchestrator.

---

## 3. Target Execution Trust Boundary

```
+--------------------------------------------------------------------------------------------------+
|                                    TRUSTED PARENT ORCHESTRATOR                                   |
|                                                                                                  |
|   +------------------------------------------------------------------------------------------+   |
|   | ChiefSecurityOrchestrator & AgentWorker                                                  |   |
|   |  - Task Leasing, CAS Fencing Tokens, Heartbeat Reaper                                    |   |
|   +------------------------------------------------------------------------------------------+   |
|                                             |                                                    |
|                                             v                                                    |
|   +------------------------------------------------------------------------------------------+   |
|   | BinaryWorkerSupervisor (Process Lifecycle Manager)                                       |   |
|   |  - Spawns child workers on process.execPath                                              |   |
|   |  - Enforces OS Limits (Windows Job Object / Linux prlimit / V8 --max-old-space-size)     |   |
|   |  - Process Group Tracking, Health Monitoring, Timeouts, Zombie Cleanup                   |   |
|   +------------------------------------------------------------------------------------------+   |
|            |                                                                  ^                  |
|            | 1. Dispatches JSON Task Request                                  | 2. Receives Raw  |
|            |    (Target buffer/path, budgets, fencing token)                  |    Analysis NDJSON|
|            v                                                                  |    (Unauthenticated)
|   +---------------------------------------+                                   |                  |
|   |   STRICT SECURE IPC TRUST BOUNDARY    |                                   |                  |
|   +---------------------------------------+                                   |                  |
|            |                                                                  |                  |
|            |                                                                  |                  |
|            v                                                                  |                  |
|   +---------------------------------------------------------------------------+              |   |
|   | ISOLATED BINARY ANALYSIS WORKER CHILD PROCESS                             |              |   |
|   |  - No Blackboard DB Handle        - No Assessment Key Material            |              |   |
|   |  - Isolated PrivateRuntimeRoot    - Resource Capped (CPU, Memory)         |              |   |
|   |                                                                           |              |   |
|   |  Stages:                                                                  |              |   |
|   |  [1. ELF Parser] -> [2. Candidate Detector] -> [3. Instruction Decoder]  |              |   |
|   |  -> [4. CFG Builder] -> [5. Reachability] -> [6. Taint] -> [7. Witness]   |              |   |
|   |                                                                           |              |   |
|   |  Output: Raw, unauthenticated Canonical Analysis Payloads                 |              |   |
|   +---------------------------------------------------------------------------+              |   |
|                                                                                              |   |
|   ========================= POST-IPC VALIDATION & SEALING =================================  |   |
|                                                                                              |   |
|   +------------------------------------------------------------------------------------------+   |
|   | 3. Parent Validation Engine                                                              |   |
|   |    - Strict Zod Schema Parse (Frame & Payload level)                                     |   |
|   |    - Recalculates SHA-256 Digests independently                                          |   |
|   |    - Verifies Context Consistency (assetId, binarySha256, runId, fencingToken)           |   |
|   |    - Verifies Graph Continuity (entry points, sinks, branch targets)                     |   |
|   +------------------------------------------------------------------------------------------+   |
|                                             |                                                    |
|                                             v                                                    |
|   +------------------------------------------------------------------------------------------+   |
|   | 4. Cryptographic Evidence Authority (TrustedEvidenceAuthority)                           |   |
|   |    - Holds Assessment Keyring (never exposed to child)                                   |   |
|   |    - Signs Stage Evidence: Decoder -> CFG -> Reachability -> Taint -> Witness            |   |
|   |    - Seals RFC 8785 canonical claims & HMAC-SHA256 signatures                            |   |
|   +------------------------------------------------------------------------------------------+   |
|                                             |                                                    |
|                                             v                                                    |
|   +------------------------------------------------------------------------------------------+   |
|   | 5. Authoritative Vulnerability Adjudication Bridge                                       |   |
|   |    - Requires Authenticated Evidence                                                     |   |
|   |    - Candidate Sink API & Rule Binding Enforcement                                       |   |
|   |    - Maps into 6-State Lifecycle: VERIFIED / FALSE_POSITIVE / MITIGATED / CANDIDATE      |   |
|   |    - Consumes Single-Use Witness Evidence atomically                                     |   |
|   +------------------------------------------------------------------------------------------+   |
|                                             |                                                    |
|                                             v                                                    |
|   +------------------------------------------------------------------------------------------+   |
|   | 6. Authoritative Persistence (SqliteBlackboardStorage)                                   |   |
|   |    - Atomic Transaction: tasks (complete), findings, observations, evidence, outbox      |   |
|   +------------------------------------------------------------------------------------------+   |
+--------------------------------------------------------------------------------------------------+
```

### 3.1 Strict Separation of Concepts
To eliminate trust boundary confusion, Phase 3A establishes clear distinctions:
1. **Worker-Produced Analysis Output:** Raw, untrusted, unauthenticated JSON objects produced by the child process (e.g. instruction lists, basic blocks, reachability paths). These have zero evidential weight.
2. **Parent-Validated Analysis Output:** Analysis output that has successfully passed parent-side structural validation, Zod schema conformance, digest recalculation, and context verification.
3. **Cryptographically Authenticated Evidence:** Data sealed by the parent's `TrustedEvidenceAuthority` with an assessment-specific HMAC-SHA256 signature, canonicalized via RFC 8785, bound to an active run, and stored in `analysis_evidence_records`.
4. **Vulnerability Adjudication:** Authoritative 6-state lifecycle classification performed solely within the parent by `VulnerabilityAdjudicationBridge` consuming authenticated evidence.

---

## 4. Secure IPC Protocol Specification

### 4.1 Wire Framing & Transport
- **Transport:** Stdio streams (`stdin` / `stdout`). Standard error (`stderr`) is captured exclusively for diagnostic logging.
- **Framing:** Newline-Delimited JSON (NDJSON) UTF-8 records.
- **Size Ceilings:**
  - Control frames (handshake, heartbeat, status, cancel): **Max 64 KB**.
  - Payload frames (transferring decoded blocks, reachability, or taint facts): **Max 16 MB** per stream, with a hard transmission budget. If an analysis exceeds 16 MB, it must be chunked or fail closed with `AnalysisResourceConstraintError`.
- **Validation:** Every inbound line is parsed via `JSON.parse` and validated with `zod.strictObject()`. Trailing garbage or unknown properties trigger immediate protocol failure.

### 4.2 Message Schemas & Discriminated Union
The protocol is versioned (`protocol_version: "1.0.0"`) and defines strict request/response frames:

#### Parent-to-Worker Request (`BinaryWorkerRequest`):
```ts
export const binaryWorkerRequestSchema = z.discriminatedUnion("kind", [
  // 1. Initial Handshake & Configuration
  z.strictObject({
    kind: z.literal("init"),
    protocol_version: z.literal("1.0.0"),
    session_id: z.string().uuid(),
    worker_id: z.string(),
    max_memory_bytes: z.number().int().positive(),
  }),

  // 2. Task Dispatch Request
  z.strictObject({
    kind: z.literal("analyze_binary"),
    protocol_version: z.literal("1.0.0"),
    request_id: z.string().uuid(),
    assessment_id: z.string(),
    asset_id: z.string(),
    run_id: z.string(),
    task_id: z.string(),
    fencing_token: z.number().int().positive(),
    binary_sha256: z.string().regex(/^[0-9a-f]{64}$/i),
    architecture: z.enum(["x86_64", "ARM", "ARM32", "Thumb", "MIPS_BE", "MIPS_LE"]),
    target_path: z.string(),
    // Base64-encoded chunk or filesystem reference within private root
    binary_data_base64: z.string().optional(),
    analysis_depth: z.enum(["shallow_symbols", "cfg_reachability", "full_proof"]),
    resource_limits: z.strictObject({
      timeout_ms: z.number().int().positive(),
      max_instructions: z.number().int().positive(),
      max_cfg_blocks: z.number().int().positive(),
      max_reachability_paths: z.number().int().positive(),
    }),
  }),

  // 3. Task Cancellation Request
  z.strictObject({
    kind: z.literal("cancel"),
    request_id: z.string().uuid(),
    task_id: z.string(),
    reason: z.string(),
  }),
]);
```

#### Worker-to-Parent Response (`BinaryWorkerResponse`):
```ts
export const binaryWorkerResponseSchema = z.discriminatedUnion("kind", [
  // 1. Worker Ready Frame
  z.strictObject({
    kind: z.literal("ready"),
    worker_id: z.string(),
    pid: z.number().int().positive(),
    supported_architectures: z.array(z.string()),
  }),

  // 2. Incremental Progress Checkpoint Frame
  z.strictObject({
    kind: z.literal("checkpoint"),
    request_id: z.string().uuid(),
    task_id: z.string(),
    stage: z.enum(["PARSE", "DECODE", "CFG", "REACHABILITY", "TAINT", "WITNESS"]),
    stage_outcome: z.enum(["SUCCESS", "PARTIAL", "FAILED"]),
    progress_percentage: z.number().min(0).max(100),
  }),

  // 3. Complete Stage Analysis Result Frame
  z.strictObject({
    kind: z.literal("analysis_result"),
    request_id: z.string().uuid(),
    task_id: z.string(),
    run_id: z.string(),
    asset_id: z.string(),
    binary_sha256: z.string().regex(/^[0-9a-f]{64}$/i),
    fencing_token: z.number().int().positive(),
    parsed_metadata: rawBinaryMetadataSchema,
    candidates: z.array(rawCandidateSchema),
    decoder_payload: rawDecoderPayloadSchema.optional(),
    cfg_payload: rawCfgPayloadSchema.optional(),
    reachability_payload: rawReachabilityPayloadSchema.optional(),
    taint_payload: rawTaintPayloadSchema.optional(),
    witness_payload: rawWitnessPayloadSchema.optional(),
    execution_time_ms: z.number().nonnegative(),
  }),

  // 4. Analysis Failure Frame
  z.strictObject({
    kind: z.literal("analysis_failure"),
    request_id: z.string().uuid(),
    task_id: z.string(),
    code: z.enum([
      "TIMEOUT",
      "RESOURCE_EXHAUSTED",
      "PARSER_CRASH",
      "DECODE_HALTED",
      "CANCELLED",
      "INTERNAL_ERROR",
    ]),
    message: z.string(),
    partial_results_retained: z.boolean(),
  }),
]);
```

### 4.3 Replay, Fencing, and Correlation Rules
1. **Fencing Token Enforcement:** Every `analyze_binary` request carries the task's active `fencing_token`. Responses carrying an expired or mismatched token are rejected by the parent orchestrator.
2. **Correlation ID:** Every message carries a unique `request_id` (UUIDv4). Responses that do not match the pending `request_id` are dropped as out-of-order or duplicate.
3. **Run ID Freshness:** The worker echoes the `run_id` issued by the parent. If the parent marks the run completed or revoked during analysis, incoming worker results are rejected.

---

## 5. Comprehensive Threat Model & Security Evaluation

| # | Threat Scenario | Attack Vector & Impact | Mitigated in Phase 3A? | Architectural Defense & Mitigation Mechanism |
|---|---|---|---|---|
| **T-1** | **Malformed IPC Messages** | Attacker/corrupted worker sends invalid JSON, prototype pollution keys (`__proto__`), or oversized frames. | **YES** | Strict Zod schemas with `.strictObject()`, NDJSON framing bounded at 64 KB for control and 16 MB for data, `JSON.parse` with no prototype instantiation. |
| **T-2** | **Forged Worker Output** | Worker fabricates reachability paths or claims a sink is unreachable to suppress a finding. | **YES** | Worker outputs are unauthenticated. Parent recalculates SHA-256 digests, verifies CFG hash continuity, enforces candidate sink API matching, and signs evidence using parent-held keys. |
| **T-3** | **Cross-Assessment Message Injection** | Compromised worker claims a finding belongs to assessment `asm_B` while executing in `asm_A`. | **YES** | Parent verifies `response.assessment_id === task.assessment_id`. Mismatches trigger immediate worker termination and `CROSS_ASSESSMENT_REUSE` rejection. |
| **T-4** | **Stale Run ID Reuse** | Worker submits results after an assessment run has been revoked or completed. | **YES** | Parent checks `runManager.verifyRunFreshness(runId)`. If status is `COMPLETED` or `REVOKED`, results fail closed (`RUN_COMPLETED` / `RUN_REVOKED`). |
| **T-5** | **Stale Fencing Token** | Delayed response from a timed-out worker attempts to overwrite a re-claimed task. | **YES** | SQLite CAS update on `tasks` table enforces `WHERE id = ? AND fencing_token = ?`. Outdated completions fail with zero rows affected. |
| **T-6** | **Worker Process Crash (Native SIGSEGV/SIGABRT)** | Malformed ELF triggers a crash in native Capstone or C++ bindings. | **YES** | `ProviderProcessSupervisor` detects unexpected exit, cleans up process group, leaves parent orchestrator unaffected, and increments retry count via `blackboard.tasks.retryTask`. |
| **T-7** | **Worker Hang / Infinite Loop** | Complex CFG with indirect jump cycles causes infinite analysis loop. | **YES** | Parent `runHandlerWithTimeout` fires `AbortController`, sends `cancel` frame, waits 2,000ms, and escalates to forceful OS process kill (SIGKILL / Job Object terminate). |
| **T-8** | **Child Process Termination** | OS OOM killer or administrator terminates worker process. | **YES** | Parent supervisor catches child `exit` event, logs reason, updates task to retry or failure, and cleans up temporary private root. |
| **T-9** | **Process Tree & Zombie Cleanup** | Child worker spawns child subprocesses (e.g. tools, helper scripts) that remain running. | **YES** | Integrates REA's `ProcessOwnership`: on Linux, scans and signals PGID; on Windows, attaches child to native Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. |
| **T-10** | **Memory Exhaustion (Allocation Bomb)** | Binary contains millions of fake symbols designed to consume all host RAM. | **YES** | Worker spawned with `--max-old-space-size=512`. On Linux, clamped via `prlimit --as`. On Windows, Job Object enforces commit ceiling. Exceeding limit terminates worker safely without killing parent. |
| **T-11** | **CPU Exhaustion (Denial of Service)** | Malicious binary forces excessive CPU utilization across all cores. | **YES** | Worker concurrency capped via `ChiefSecurityOrchestrator` (`maxConcurrency`). Per-task CPU timeout limits runaways. Linux limits enforce `cpu_seconds`. |
| **T-12** | **Oversized Payloads** | Worker sends 500 MB AST or instruction trace to exhaust parent memory. | **YES** | Protocol defines strict 16 MB ceiling on payload transfer. Streaming buffer checks reject transmissions exceeding budget. |
| **T-13** | **Path Traversal Attacks** | Binary metadata claims file path is `../../../../etc/shadow`. | **YES** | Target binary read via `SafeElfReader` using memory buffers or canonicalized absolute paths within `PrivateRuntimeRoot`. Worker has no access to host roots. |
| **T-14** | **Evidence Replay Across Candidates** | Valid reachability for `system` replayed to verify candidate `strcpy`. | **YES** | Parent `VulnerabilityAdjudicationBridge` strictly checks `trustedReachability.payload.target === candidate.sinkApi` and candidate ruleId. |
| **T-15** | **Parent Process Restart / Crash** | Parent orchestrator restarts while child workers are executing. | **YES** | Child workers monitor parent stdin EOF. When parent terminates, stdin closes, causing child worker process to self-terminate immediately. |
| **T-16** | **Compromised Worker Arbitrary Execution** | Attacker achieves full RCE inside the child worker process via ELF exploit. | **PARTIAL** | Worker has no database connection, no HMAC keys, and cannot sign evidence or update blackboard state. **Out of scope:** Phase 3A does not provide kernel-level virtualization or hardware enclaves; a kernel zero-day could escape. |

---

## 6. Implementation Milestones

```
+---------------------------------------------------------------------------------------------------------+
|                                    PHASE 3A IMPLEMENTATION ROADMAP                                      |
+---------------------------------------------------------------------------------------------------------+
|                                                                                                         |
|   [Milestone 1: IPC Protocol Contracts]                                                                 |
|   - Define src/security/binary/ipc/binaryWorkerProtocol.ts (Zod schemas, types, limits)                 |
|   - Add wire frame serialization & stream parsing helpers (NDJSON, 64KB/16MB budgets)                   |
|   - Unit test schemas against malformed, oversized, and prototype-polluting payloads                    |
|                                     |                                                                   |
|                                     v                                                                   |
|   [Milestone 2: Child Worker Process Runtime]                                                           |
|   - Create src/composition/binaryAnalysisWorkerProcess.ts (child entrypoint)                            |
|   - Wire safe ELF reading, decoding, CFG, reachability, taint, witness inside worker                    |
|   - Implement stdin/stdout frame loop with parent heartbeat & self-termination on stdin EOF             |
|                                     |                                                                   |
|                                     v                                                                   |
|   [Milestone 3: Process Supervisor & Lifecycle Manager]                                                 |
|   - Create src/security/binary/supervisor/BinaryWorkerSupervisor.ts                                     |
|   - Spawn child on process.execPath with PrivateRuntimeRoot & memory limits                             |
|   - Manage process tree ownership (ProcessOwnership, Job Objects, prlimit)                              |
|   - Implement timeout, cancellation, crash recovery, and auto-restart backoff                           |
|                                     |                                                                   |
|                                     v                                                                   |
|   [Milestone 4: Parent Evidence Sealer & Adjudication Adapter]                                          |
|   - Create BinaryAnalysisWorkerBridge.ts in parent orchestrator                                         |
|   - Validate raw worker payloads, recalculate SHA-256 digests, verify context                           |
|   - Seal validated payloads using TrustedEvidenceAuthority stage signers                                |
|   - Adjudicate findings via VulnerabilityAdjudicationBridge                                             |
|                                     |                                                                   |
|                                     v                                                                   |
|   [Milestone 5: Orchestration & Blackboard Integration]                                                 |
|   - Refactor BinaryAnalysisWorker.ts to delegate to BinaryWorkerSupervisor                              |
|   - Integrate with ChiefSecurityOrchestrator and AgentWorker task claiming/fencing                      |
|   - Persist findings, observations, and evidence atomically in blackboard.db                            |
|                                     |                                                                   |
|                                     v                                                                   |
|   [Milestone 6: Independent Acceptance & Adversarial Testing]                                           |
|   - Implement tests/security/binary/multiProcessAcceptance.test.ts                                      |
|   - Execute 14 real child-process adversarial test cases                                                |
|   - Validate clean build, check:fast, and 100% test pass rate                                           |
+---------------------------------------------------------------------------------------------------------+
```

### Detailed Milestone Specifications

#### Milestone 1: IPC Contracts and Wire Framing
- **Files to Add:**
  - `src/security/binary/ipc/binaryWorkerProtocol.ts`
  - `src/security/binary/ipc/binaryWorkerProtocol.test.ts`
- **Responsibilities:** Define Zod schemas for all parent-worker frames, stream framing parser, serialization helpers, and transfer limits.
- **Security Invariants:** No prototype inheritance allowed; schema strictly rejects undeclared properties; control frames capped at 64 KB; payload frames capped at 16 MB.
- **Rollback:** Module is isolated and additive; delete `src/security/binary/ipc/`.

#### Milestone 2: Worker Process Runtime
- **Files to Add:**
  - `src/composition/binaryAnalysisWorkerProcess.ts`
  - `src/security/binary/worker/BinaryWorkerEngine.ts`
- **Responsibilities:** Standalone CLI entrypoint that reads tasks from stdin, invokes analysis pipeline, emits incremental checkpoints, and writes completed analysis frames to stdout.
- **Security Invariants:** Worker never imports `secureKeyring.ts`, `SqliteBlackboardStorage`, or `TrustedEvidenceAuthority`. Exits immediately if stdin closes.
- **Rollback:** Standalone executable script; does not alter existing in-process workers.

#### Milestone 3: Process Supervisor and Lifecycle Manager
- **Files to Add:**
  - `src/security/binary/supervisor/BinaryWorkerSupervisor.ts`
  - `src/security/binary/supervisor/BinaryWorkerSupervisor.test.ts`
- **Responsibilities:** Launch child worker on `process.execPath`, configure `PrivateRuntimeRoot`, apply platform-specific memory and CPU limits, manage stdio pipes, monitor health, enforce timeouts, handle SIGTERM/SIGKILL escalation, and clean up process trees.
- **Security Invariants:** Reuses `src/process/ProcessOwnership.ts`. Process groups tracked by unique token; zero orphaned child processes allowed on timeout or crash.
- **Rollback:** Unit tests run against supervisor; no production changes to orchestrator yet.

#### Milestone 4: Parent Evidence Sealer & Adjudication Adapter
- **Files to Add:**
  - `src/security/binary/supervisor/ParentEvidenceValidator.ts`
  - `src/security/binary/supervisor/ParentEvidenceValidator.test.ts`
- **Responsibilities:** Receive raw worker responses, parse schemas, re-canonicalize payloads to compute SHA-256 digests, verify context against active task, pass validated payloads to `TrustedEvidenceAuthority` for cryptographic signing, and invoke `VulnerabilityAdjudicationBridge`.
- **Security Invariants:** Parent independently computes digests; worker cannot supply its own signature or digest. Adjudication is strictly fail-closed.
- **Rollback:** Isolated component.

#### Milestone 5: Orchestration & Blackboard Integration
- **Files to Modify:**
  - `src/application/security/workers/BinaryAnalysisWorker.ts`
  - `src/application/security/workers/BinaryAnalysisWorker.test.ts`
- **Responsibilities:** Replace direct in-process analysis execution in `BinaryAnalysisWorker` with delegation to `BinaryWorkerSupervisor`. Wire task results to `completeTask` with CAS fencing tokens.
- **Security Invariants:** Blackboard DB mutation occurs only in the parent orchestrator after evidence validation.
- **Rollback:** Revert `BinaryAnalysisWorker.ts` to previous in-process implementation if worker spawning fails.

#### Milestone 6: Independent Adversarial Verification Suite
- **Files to Add:**
  - `tests/security/binary/multiProcessAcceptance.test.ts`
- **Responsibilities:** Execute end-to-end multi-process adversarial test cases with real child processes.
- **Security Invariants:** All 14 independent acceptance criteria verified under real OS conditions.

---

## 7. Independent Adversarial Acceptance Tests

The following 14 independent acceptance tests must be implemented and verified against real spawned child processes:

1. **Worker Termination During Analysis (Crash Test):**
   - *Scenario:* Send `SIGKILL` or crash the child worker process (`process.exit(139)`) during active CFG reachability analysis.
   - *Expected:* Parent supervisor detects exit, marks task retryable or failed via `blackboard.tasks.retryTask`, cleans up process group, leaves orchestrator healthy, and prevents database corruption.
2. **Worker Auto-Restart & Recovery:**
   - *Scenario:* Worker process crashes; parent receives subsequent analysis task.
   - *Expected:* Supervisor respawns a fresh child worker with clean runtime root and completes the new task successfully.
3. **Forged Worker Output Rejection:**
   - *Scenario:* Worker sends an analysis result where the claimed payload digest does not match the actual canonical digest of the payload.
   - *Expected:* Parent recalculates digest, detects mismatch (`INVALID_PAYLOAD_DIGEST`), rejects evidence signing, and sets finding lifecycle to `INCONCLUSIVE`.
4. **Cross-Assessment Message Rejection:**
   - *Scenario:* Worker returns an analysis result containing `assessmentId: "asm_foreign"` when task belonged to `"asm_local"`.
   - *Expected:* Parent rejects result with `CROSS_ASSESSMENT_REUSE`, kills worker process, and logs security alert.
5. **Stale Fencing Token Rejection:**
   - *Scenario:* Worker is delayed; parent reaps lease and increments fencing token. Worker finally responds with old token.
   - *Expected:* Parent attempts `completeTask` with old token; SQLite CAS rejects update with zero rows affected.
6. **Stale Run ID Rejection:**
   - *Scenario:* Worker finishes analysis under a `runId` that the parent revoked during execution.
   - *Expected:* Parent verifier rejects with `RUN_REVOKED`; no evidence is sealed or adjudicated.
7. **Single-Use Witness Replay Protection:**
   - *Scenario:* Worker emits the same witness ID across two different candidates.
   - *Expected:* First candidate consumes witness; second candidate adjudication fails closed with `replay detected`.
8. **Message Size Limit Enforcement:**
   - *Scenario:* Worker attempts to send a 20 MB payload on stdout.
   - *Expected:* Parent stream decoder detects buffer exceeding 16 MB limit, aborts stream, terminates child, and records `AnalysisResourceConstraintError`.
9. **Worker Timeout Enforcement:**
   - *Scenario:* Worker enters an infinite loop (`while(true) {}`).
   - *Expected:* Parent timeout fires after configured deadline (e.g. 5,000ms), sends `cancel` frame, escalates to `SIGKILL` after 2,000ms, and releases task lease.
10. **Process Tree & Zombie Cleanup:**
    - *Scenario:* Worker spawns an orphan background helper process (`node -e "setInterval(()=>{},1000)"`) and exits.
    - *Expected:* Parent `ProcessOwnership` cleanup signals the entire process group / Windows Job Object; orphan process is terminated.
11. **Worker Key Material Isolation:**
    - *Scenario:* Inspect child worker memory and environment variables.
    - *Expected:* No assessment keys, HMAC secrets, or keyring paths exist in worker process environment or memory space.
12. **Incomplete Analysis Handling:**
    - *Scenario:* Worker encounters unsupported opcodes (e.g. x86-64 `0x25`) resulting in `PARTIAL` decode outcome.
    - *Expected:* Reachability evaluates to `INCONCLUSIVE`; candidate cannot be marked `FALSE_POSITIVE` or `VERIFIED`.
13. **Parent Restart & Orphan Cleanup:**
    - *Scenario:* Kill parent orchestrator process (`SIGKILL`) while child worker is running.
    - *Expected:* Child worker detects EOF on stdin and terminates cleanly within 500ms without leaving zombie processes.
14. **Atomic Result & Outbox Persistence:**
    - *Scenario:* Completed analysis result is accepted by parent.
    - *Expected:* Task completion, findings creation, observations recording, and outbox event insertion occur within a single atomic SQLite transaction.

---

## 8. Implementation Task Checklist

- [ ] **Milestone 1 — IPC Contracts:**
  - [ ] Implement `src/security/binary/ipc/binaryWorkerProtocol.ts` with Zod schemas.
  - [ ] Implement stream framing & NDJSON parser with 64 KB / 16 MB budget limits.
  - [ ] Write unit tests for protocol schemas in `binaryWorkerProtocol.test.ts`.
- [ ] **Milestone 2 — Child Worker Process Runtime:**
  - [ ] Implement `src/composition/binaryAnalysisWorkerProcess.ts` entrypoint.
  - [ ] Implement `src/security/binary/worker/BinaryWorkerEngine.ts` coordinating analysis stages.
  - [ ] Implement stdin/stdout communication loop with EOF monitoring.
- [ ] **Milestone 3 — Process Supervisor:**
  - [ ] Implement `src/security/binary/supervisor/BinaryWorkerSupervisor.ts`.
  - [ ] Integrate with REA's `ProcessOwnership` (PGID tracking & Windows Job Objects).
  - [ ] Implement memory limits, timeouts, cancellation, and auto-restart backoff.
  - [ ] Write unit tests in `BinaryWorkerSupervisor.test.ts`.
- [ ] **Milestone 4 — Parent Evidence Sealer & Adjudication:**
  - [ ] Implement `src/security/binary/supervisor/ParentEvidenceValidator.ts`.
  - [ ] Wire parent validation to `TrustedEvidenceAuthority` for cryptographic signing.
  - [ ] Wire validated evidence to `VulnerabilityAdjudicationBridge`.
  - [ ] Write unit tests in `ParentEvidenceValidator.test.ts`.
- [ ] **Milestone 5 — Blackboard & Orchestrator Integration:**
  - [ ] Refactor `BinaryAnalysisWorker.ts` to delegate to `BinaryWorkerSupervisor`.
  - [ ] Ensure atomic SQLite persistence for findings, tasks, evidence, and outbox.
  - [ ] Verify existing test suite passes without regressions.
- [ ] **Milestone 6 — Adversarial Acceptance Suite:**
  - [ ] Implement `tests/security/binary/multiProcessAcceptance.test.ts` covering all 14 test cases.
  - [ ] Execute complete local gate: `npm run check:fast` and `vitest run`.
  - [ ] Author Phase 3A completion and verification report.

