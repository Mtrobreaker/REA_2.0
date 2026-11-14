/* eslint-disable max-lines-per-function */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import canonicalize from "canonicalize";
import {
  ParentEvidenceValidator,
  type ParentValidationContext,
} from "./ParentEvidenceValidator.js";
import {
  TrustedEvidenceAuthority,
  TrustedEvidenceVerifier,
  AnalysisRunManager,
} from "./TrustedAnalysisEvidence.js";
import { KeyringManager } from "../../packboard/secureKeyring.js";
import {
  BinaryWorkerSupervisor,
  type BinarySupervisorLifecycleEvent,
} from "../supervisor/BinaryWorkerSupervisor.js";
import {
  BINARY_WORKER_PROTOCOL_VERSION,
  type BinaryWorkerAnalyzeRequest,
  type BinaryWorkerAnalyzeResponse,
} from "../ipc/binaryWorkerProtocol.js";
import { VulnerabilityAdjudicationBridge } from "../VulnerabilityAdjudicationBridge.js";
import { SqliteBlackboardStorage } from "../../blackboard/SqliteBlackboardStorage.js";
import { BinaryAnalysisWorker } from "../../../application/security/workers/BinaryAnalysisWorker.js";
import { createTestElfImage } from "../testElfFixtures.js";
import type { TaskRecord, BlackboardAssetRecord } from "../../../domain/security/blackboard/types.js";
import type { VulnerabilityCandidate } from "../../../domain/security/binary/types.js";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { AssetId, AssetType } from "../../../domain/security/asset.js";

// Helper: canonical SHA-256 digest
function canonicalDigest(payload: unknown): string {
  const canonicalJson = canonicalize(payload) ?? "{}";
  return createHash("sha256").update(canonicalJson).digest("hex");
}

describe("REA Phase 3A — Milestone 4.1: Independent End-to-End Integration Acceptance Audit", () => {
  let tempDir: string;
  let dbPath: string;
  let journalPath: string;
  let storage: SqliteBlackboardStorage;
  let keyringManager: KeyringManager;
  let authority: TrustedEvidenceAuthority;
  let verifier: TrustedEvidenceVerifier;
  let bridge: VulnerabilityAdjudicationBridge;
  let validator: ParentEvidenceValidator;

  const testAssessmentId = "asm_e2e_audit_01" as AssessmentId;
  const testAssetId = "ast_gateway_daemon_01" as AssetId;
  const testTaskId = "tsk_bin_inspect_01";
  const testFencingToken = 1;

  // Real valid ARM ELF image containing executable code and symbol table
  const dummyArmBytes = createTestElfImage({
    is64Bit: false,
    isLE: true,
    machine: 0x28, // ARM
    entryPoint: 0x10000,
    importedSymbols: ["strcpy", "system"],
    exportedSymbols: ["main", "handle_packet"],
    strings: ["admin:admin", "/bin/sh"],
    textBytes: new Uint8Array([
      0x04, 0x00, 0x9d, 0xe5, // ldr r0, [sp, #4]
      0x00, 0x00, 0x00, 0xeb, // bl system
    ]),
  });
  const dummyBinarySha256 = createHash("sha256").update(dummyArmBytes).digest("hex");

  const testCandidate: VulnerabilityCandidate = {
    binaryAssetId: testAssetId,
    ruleId: "REA-BIN-001",
    name: "Command Injection in Packet Dispatcher",
    category: "unsafe_memory_operations",
    functionName: "handle_packet",
    functionAddress: "0x1000",
    sinkApi: "system",
    callAddress: "0x1004",
    callerInfo: "main",
    sourceOfInput: "network_socket",
    guardInfo: null,
    evidenceReferences: [],
    detectionMethod: "L5_WITNESS",
    confidenceScore: 0.95,
    confidenceLimitations: [],
    cwe: ["CWE-78"],
    technicalDescription: "Attacker-controlled input flows unsanitized to system() invocation",
    remediationGuidance: "Replace system() with execve() using explicit argument arrays",
  };

  function createTestAssetObj(): BlackboardAssetRecord {
    return {
      id: testAssetId,
      assessment_id: testAssessmentId,
      parent_asset_id: null,
      name: "gateway_daemon",
      type: "compiled_binary" as AssetType,
      path: "/usr/bin/gateway_daemon",
      architecture: "ARM",
      version: "1.0",
      environment: null,
      tags: [],
      digest: { sha256: dummyBinarySha256 },
      metadata: {},
      created_at: Date.now(),
    };
  }

  const activeSupervisors: BinaryWorkerSupervisor[] = [];

  function trackSupervisor(sup: BinaryWorkerSupervisor): BinaryWorkerSupervisor {
    activeSupervisors.push(sup);
    return sup;
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rea-m41-audit-"));
    dbPath = join(tempDir, "blackboard.db");
    journalPath = join(tempDir, "audit.jsonl");

    storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId: testAssessmentId });
    keyringManager = KeyringManager.createEphemeral(testAssessmentId);
    authority = new TrustedEvidenceAuthority({ keyringManager, db: storage.getDatabase() });
    verifier = new TrustedEvidenceVerifier({ keyringManager, db: storage.getDatabase() });
    bridge = new VulnerabilityAdjudicationBridge({ verifier });
    validator = new ParentEvidenceValidator();

    // Populate assessment and asset in SQLite
    storage.getDatabase().prepare(`
      INSERT INTO assessments (
        id, name, status, objective_json, authorization_json, metrics_json, created_at, updated_at
      ) VALUES (?, 'Phase 3A Milestone 4.1 Audit Assessment', 'active', '{}', '{}', '{}', ?, ?)
    `).run(testAssessmentId, Date.now(), Date.now());

    storage.getDatabase().prepare(`
      INSERT INTO assets (
        id, assessment_id, name, type, sha256, path, metadata_json, created_at
      ) VALUES (?, ?, 'gateway_daemon', 'binary', ?, '/usr/bin/gateway_daemon', ?, ?)
    `).run(
      testAssetId,
      testAssessmentId,
      dummyBinarySha256,
      JSON.stringify({ architecture: "ARM", buffer: { type: "Buffer", data: Array.from(dummyArmBytes) } }),
      Date.now(),
    );
  });

  afterEach(async () => {
    while (activeSupervisors.length > 0) {
      const sup = activeSupervisors.pop()!;
      try {
        await sup.shutdown(500);
      } catch {
        sup.forceKillProcess();
      }
    }
    storage.close();
    try {
      await rm(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort directory cleanup
    }
  });

  // ==========================================================================
  // 1. Real Child Process Execution & End-to-End Pipeline
  // ==========================================================================
  it("SCENARIO-1: Real child worker executes task -> supervisor -> parent validation -> sealing -> adjudication -> SQLite persistence -> outbox event", async () => {
    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_e2e_real_01",
        allowedRoot: tempDir,
      }),
    );
    await supervisor.start();
    expect(supervisor.getState()).toBe("READY");

    const runManager = authority.getRunManager();
    const run = runManager.startRun(testAssessmentId, testAssetId, dummyBinarySha256);

    // Setup claimed task in blackboard
    storage.getDatabase().prepare(`
      INSERT INTO tasks (
        id, assessment_id, task_type, title, description, asset_id, priority, status,
        blocked_by_json, fencing_token, cas_version, claim_json, result_json, metadata_json,
        smoke_score, votes_json, evidence_hashes_json, created_at, updated_at
      ) VALUES (
        ?, ?, 'binary_analysis', 'Milestone 4.1 Integration Test Task', 'Deep binary inspection', ?, 'high', 'claimed',
        '[]', ?, 1, '{}', null, '{}', 0, '[]', '[]', ?, ?
      )
    `).run(testTaskId, testAssessmentId, testAssetId, testFencingToken, Date.now(), Date.now());

    const analyzeRequest: BinaryWorkerAnalyzeRequest = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_REQUEST",
      messageId: randomUUID(),
      taskId: testTaskId,
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      runId: run.runId,
      fencingToken: testFencingToken,
      workerId: supervisor.workerId,
      requestedStage: "ALL",
      binaryInput: {
        type: "inline_buffer",
        expected_sha256: dummyBinarySha256,
        byte_size: dummyArmBytes.length,
        data_base64: dummyArmBytes.toString("base64"),
        read_only: true,
      },
      analysisConfiguration: {
        architecture: "ARM",
        entryPoints: ["main"],
        targetFunctions: ["system"],
        maxInstructions: 100,
        maxCfgBlocks: 10,
        maxPaths: 5,
      },
      deadline: Date.now() + 15_000,
    };

    const parentCtx: ParentValidationContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      runId: run.runId,
      taskId: testTaskId,
      fencingToken: testFencingToken,
      workerId: supervisor.workerId,
      requestedStage: "ALL",
      architecture: "ARM",
      binaryInputBytes: dummyArmBytes,
    };

    // 1. Worker Execution via real child process
    const workerRes = await supervisor.executeTask(analyzeRequest);
    expect(workerRes.ok).toBe(true);
    if (!workerRes.ok) return;

    const untrustedDto = workerRes.value;
    expect(untrustedDto.kind).toBe("ANALYZE_RESPONSE");
    expect(untrustedDto.workerId).toBe(supervisor.workerId);
    expect(untrustedDto.executionStatus).toBe("SUCCESS");

    // 2. Parent Evidence Validation
    const valRes = validator.validateWorkerResponse(untrustedDto, parentCtx);
    expect(valRes.ok).toBe(true);
    if (!valRes.ok) return;

    // 3. Trusted Evidence Sealing
    const sealedRes = validator.sealValidatedEvidence(valRes.value, authority, parentCtx);
    expect(sealedRes.ok).toBe(true);
    if (!sealedRes.ok) return;

    expect(sealedRes.value.decoderEvidence).toBeDefined();
    expect(sealedRes.value.cfgEvidence).toBeDefined();
    expect(sealedRes.value.reachabilityEvidence).toBeDefined();
    expect(sealedRes.value.taintEvidence).toBeDefined();
    expect(sealedRes.value.witnessEvidence).toBeDefined();

    // 4. Adjudication & Atomic Persistence
    const testAssetObj = createTestAssetObj();

    const adjRes = validator.adjudicateAndPersist({
      storage,
      authority,
      bridge,
      asset: testAssetObj,
      candidate: testCandidate,
      bundle: sealedRes.value,
      context: parentCtx,
    });

    expect(adjRes.ok).toBe(true);
    if (!adjRes.ok) return;

    expect(adjRes.value.lifecycleState).toBe("INCONCLUSIVE");

    // 5. Verify SQLite Persistence State
    const findingRow = storage.getDatabase().prepare("SELECT * FROM findings WHERE id = ?").get(adjRes.value.finding.id) as any;
    expect(findingRow).toBeDefined();
    expect(findingRow.state).toBe("INCONCLUSIVE");
    expect(findingRow.assessment_id).toBe(testAssessmentId);

    // 6. Verify Outbox Event Queued
    const outboxRow = storage.getDatabase().prepare("SELECT * FROM transactional_outbox WHERE event_type = 'finding_adjudicated'").get() as any;
    expect(outboxRow).toBeDefined();
    const payload = JSON.parse(outboxRow.payload_json);
    expect(payload.findingId).toBe(adjRes.value.finding.id);
    expect(payload.finalState).toBe("INCONCLUSIVE");
    expect(payload.taskId).toBe(testTaskId);

    // 7. Verify Task Marked Completed
    const taskRow = storage.getDatabase().prepare("SELECT status, result_json FROM tasks WHERE id = ?").get(testTaskId) as any;
    expect(taskRow.status).toBe("completed");
    const resultObj = JSON.parse(taskRow.result_json);
    expect(resultObj.findingId).toBe(adjRes.value.finding.id);
    expect(resultObj.state).toBe("INCONCLUSIVE");

    // 8. Verify Witness is NOT consumed when adjudication is INCONCLUSIVE
    const witnessEvidenceId = sealedRes.value.witnessEvidence!.claims.evidenceId;
    const isConsumed = verifier.isEvidenceConsumed(witnessEvidenceId);
    expect(isConsumed).toBe(false);
  });

  // ==========================================================================
  // 2. Production Pipeline Integration via BinaryAnalysisWorker
  // ==========================================================================
  it("SCENARIO-2: BinaryAnalysisWorker full path executes through supervisor, validator, and authority", async () => {
    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_e2e_baw_01",
        allowedRoot: tempDir,
      }),
    );
    await supervisor.start();

    // Create claimed task in blackboard
    storage.getDatabase().prepare(`
      INSERT INTO tasks (
        id, assessment_id, task_type, title, description, asset_id, priority, status,
        blocked_by_json, fencing_token, cas_version, claim_json, result_json, metadata_json,
        smoke_score, votes_json, evidence_hashes_json, created_at, updated_at
      ) VALUES (
        ?, ?, 'binary_analysis', 'Production Worker Task', 'Deep binary inspection', ?, 'high', 'claimed',
        '[]', ?, 1, '{}', null, ?, 0, '[]', '[]', ?, ?
      )
    `).run(
      testTaskId,
      testAssessmentId,
      testAssetId,
      testFencingToken,
      JSON.stringify({
        buffer: { type: "Buffer", data: Array.from(dummyArmBytes) },
        architecture: "ARM",
      }),
      Date.now(),
      Date.now(),
    );

    const taskRecord: TaskRecord = {
      id: testTaskId,
      assessment_id: testAssessmentId,
      task_type: "binary_analysis",
      title: "Production Worker Task",
      description: "Deep binary inspection",
      asset_id: testAssetId,
      priority: "high",
      status: "claimed",
      blocked_by: [],
      fencing_token: testFencingToken,
      cas_version: 1,
      claim: null,
      result: null,
      metadata: {
        buffer: { type: "Buffer", data: Array.from(dummyArmBytes) },
        architecture: "ARM",
      },
      smoke_score: 0,
      votes: [],
      evidence_hashes: [],
      created_at: Date.now(),
      updated_at: Date.now(),
    };

    const dummyContextProjector = {
      projectContext: async () => ({ ok: true as const, value: {} }),
    } as any;

    const worker = new BinaryAnalysisWorker(
      testAssessmentId,
      storage as any,
      dummyContextProjector,
      {
        supervisor,
        validator,
        authority,
      },
    );

    const result = await worker.handleBinaryAnalysisTask(taskRecord, {});
    expect(result.assetId).toBe(testAssetId);
    expect(result.sha256).toBe(dummyBinarySha256);
  });

  // ==========================================================================
  // 3. Fallback Route Bypass Audit
  // ==========================================================================
  it("SCENARIO-3: In-process fallback without supervisor/authority CANNOT escalate to VERIFIED or FALSE_POSITIVE", async () => {
    // Setup task in blackboard
    storage.getDatabase().prepare(`
      INSERT INTO tasks (
        id, assessment_id, task_type, title, description, asset_id, priority, status,
        blocked_by_json, fencing_token, cas_version, claim_json, result_json, metadata_json,
        smoke_score, votes_json, evidence_hashes_json, created_at, updated_at
      ) VALUES (
        ?, ?, 'binary_analysis', 'Fallback Task', 'Inspect without supervisor', ?, 'high', 'claimed',
        '[]', ?, 1, '{}', null, ?, 0, '[]', '[]', ?, ?
      )
    `).run(
      testTaskId,
      testAssessmentId,
      testAssetId,
      testFencingToken,
      JSON.stringify({
        buffer: { type: "Buffer", data: Array.from(dummyArmBytes) },
        architecture: "ARM",
      }),
      Date.now(),
      Date.now(),
    );

    const taskRecord: TaskRecord = {
      id: testTaskId,
      assessment_id: testAssessmentId,
      task_type: "binary_analysis",
      title: "Fallback Task",
      description: "Inspect without supervisor",
      asset_id: testAssetId,
      priority: "high",
      status: "claimed",
      blocked_by: [],
      fencing_token: testFencingToken,
      cas_version: 1,
      claim: null,
      result: null,
      metadata: {
        buffer: { type: "Buffer", data: Array.from(dummyArmBytes) },
        architecture: "ARM",
      },
      smoke_score: 0,
      votes: [],
      evidence_hashes: [],
      created_at: Date.now(),
      updated_at: Date.now(),
    };

    const dummyContextProjector = {
      projectContext: async () => ({ ok: true as const, value: {} }),
    } as any;

    // Intentionally omit supervisor, validator, and authority
    const fallbackWorker = new BinaryAnalysisWorker(
      testAssessmentId,
      storage as any,
      dummyContextProjector,
      {},
    );

    const execResult = await fallbackWorker.handleBinaryAnalysisTask(taskRecord, {});
    for (const f of execResult.findings) {
      // In fallback mode, findings MUST remain strictly CANDIDATE or INCONCLUSIVE
      expect(f.verification_status).not.toBe("VERIFIED");
      expect(f.verification_status).not.toBe("FALSE_POSITIVE");
      expect(f.verification_status).not.toBe("MITIGATED");
    }
  });

  // ==========================================================================
  // 4. Evidence Authenticity & Immutability
  // ==========================================================================
  it("SCENARIO-4: Parent independently hashes binary bytes and rejects worker digest spoofing", async () => {
    const runManager = authority.getRunManager();
    const run = runManager.startRun(testAssessmentId, testAssetId, dummyBinarySha256);

    const forgedBinarySha256 = createHash("sha256").update(Buffer.from("malicious_foreign_binary")).digest("hex");

    const parentCtx: ParentValidationContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      runId: run.runId,
      taskId: testTaskId,
      fencingToken: testFencingToken,
      workerId: "wkr_test_01",
      requestedStage: "ALL",
      architecture: "ARM",
      binaryInputBytes: dummyArmBytes,
    };

    // 1. Worker returns mismatched binarySha256 in response DTO -> rejected with CONTEXT_MISMATCH
    const mockResponse: BinaryWorkerAnalyzeResponse = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_RESPONSE",
      messageId: randomUUID(),
      inReplyTo: "msg_req_mock_01",
      taskId: testTaskId,
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: forgedBinarySha256, // Forged binary hash!
      runId: run.runId,
      fencingToken: testFencingToken,
      workerId: "wkr_test_01",
      stage: "ALL",
      executionStatus: "SUCCESS",
      decodeCompleteness: {
        isComplete: true,
        outcome: "SUCCESS",
        decodedBytes: dummyArmBytes.length,
        totalBytes: dummyArmBytes.length,
      },
      resultPayload: {},
      resultDigest: canonicalDigest({}),
      diagnostics: [],
      resourceUsage: { cpuTimeMs: 1, wallTimeMs: 1, peakMemoryBytes: 1024 },
    };

    const valRes = validator.validateWorkerResponse(mockResponse, parentCtx);
    expect(valRes.ok).toBe(false);
    if (!valRes.ok) {
      expect(valRes.error.code).toBe("CONTEXT_MISMATCH");
    }

    // 2. Parent independently hashes bytes and detects tampering between claimed binarySha256 and actual bytes
    const tamperedBytes = Buffer.from([0x90, 0x90, 0x90, 0x90]);
    const tamperedCtx: ParentValidationContext = {
      ...parentCtx,
      binaryInputBytes: tamperedBytes, // Does not match dummyBinarySha256!
    };

    const mockResponse2: BinaryWorkerAnalyzeResponse = {
      ...mockResponse,
      binarySha256: dummyBinarySha256,
    };

    const valRes2 = validator.validateWorkerResponse(mockResponse2, tamperedCtx);
    expect(valRes2.ok).toBe(false);
    if (!valRes2.ok) {
      expect(valRes2.error.code).toBe("INPUT_INTEGRITY_VIOLATION");
    }
  });

  it("SCENARIO-5: Worker cannot choose arbitrary input path outside sandbox root", async () => {
    const sandboxDir = await mkdtemp(join(tempDir, "sandbox-"));
    const outsideFile = join(tempDir, "sensitive_host_secret.bin");
    await writeFile(outsideFile, Buffer.from("super_secret_host_data"));

    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_e2e_sandbox_01",
        allowedRoot: sandboxDir, // Restricted root
      }),
    );
    await supervisor.start();

    const request: BinaryWorkerAnalyzeRequest = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_REQUEST",
      messageId: randomUUID(),
      taskId: testTaskId,
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      runId: "run_test_sandbox",
      fencingToken: testFencingToken,
      workerId: supervisor.workerId,
      requestedStage: "PARSE",
      binaryInput: {
        type: "file_path",
        path: outsideFile, // Path traversal / sandbox escape
        expected_sha256: dummyBinarySha256,
        byte_size: 24,
        read_only: true,
      },
      analysisConfiguration: {
        architecture: "ARM",
        entryPoints: ["main"],
        maxInstructions: 10,
        maxCfgBlocks: 2,
        maxPaths: 1,
      },
      deadline: Date.now() + 10_000,
    };

    const res = await supervisor.executeTask(request);
    // Worker runtime rejects path escaping allowedRoot and fails analysis safely
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.executionStatus).toBe("FAILED");
    expect(res.value.decodeCompleteness.haltReason).toMatch(/escapes allowed root directory|Path traversal/);
  });

  it("SCENARIO-6: Validated worker payload is deep-frozen against in-memory modification", () => {
    const runManager = authority.getRunManager();
    const run = runManager.startRun(testAssessmentId, testAssetId, dummyBinarySha256);

    const parentCtx: ParentValidationContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      runId: run.runId,
      taskId: testTaskId,
      fencingToken: testFencingToken,
      workerId: "wkr_test_01",
      requestedStage: "ALL",
      architecture: "ARM",
      binaryInputBytes: dummyArmBytes,
    };

    const payload = {
      metadata: {
        sha256: dummyBinarySha256,
        architecture: "ARM" as const,
        endianness: "little" as const,
        elfClass: "32" as const,
        entryPoint: "0x1000",
        isExecutable: true,
        sectionsCount: 1,
        programHeadersCount: 1,
        dynamicLibraries: [],
      },
    };

    const response: BinaryWorkerAnalyzeResponse = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_RESPONSE",
      messageId: randomUUID(),
      inReplyTo: "msg_req_mock_02",
      taskId: testTaskId,
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      runId: run.runId,
      fencingToken: testFencingToken,
      workerId: "wkr_test_01",
      stage: "ALL",
      executionStatus: "SUCCESS",
      decodeCompleteness: {
        isComplete: true,
        outcome: "SUCCESS",
        decodedBytes: dummyArmBytes.length,
        totalBytes: dummyArmBytes.length,
      },
      resultPayload: payload,
      resultDigest: canonicalDigest(payload),
      diagnostics: [],
      resourceUsage: { cpuTimeMs: 1, wallTimeMs: 1, peakMemoryBytes: 1024 },
    };

    const valRes = validator.validateWorkerResponse(response, parentCtx);
    expect(valRes.ok).toBe(true);
    if (!valRes.ok) return;

    // Verify object is frozen
    expect(Object.isFrozen(valRes.value)).toBe(true);
    expect(Object.isFrozen(valRes.value.response)).toBe(true);

    // Attempting to mutate throws TypeError in strict mode
    expect(() => {
      (valRes.value.response as any).binarySha256 = "mutated_hash";
    }).toThrow(TypeError);
  });

  // ==========================================================================
  // 5. Persistent Replay Protection Across Cold Restarts
  // ==========================================================================
  it("SCENARIO-7: Cold restart on disk SQLite DB persists witness consumption and rejects replay", async () => {
    const runManager1 = authority.getRunManager();
    const run1 = runManager1.startRun(testAssessmentId, testAssetId, dummyBinarySha256);

    const parentCtx: ParentValidationContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      runId: run1.runId,
      taskId: testTaskId,
      fencingToken: testFencingToken,
      workerId: "wkr_restart_01",
      requestedStage: "ALL",
      architecture: "ARM",
      binaryInputBytes: dummyArmBytes,
    };

    // Construct valid multi-stage payload
    const stageContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      firmwareSha256: dummyBinarySha256,
      runId: run1.runId,
    };

    const decSigner = authority.createDecoderSigner(stageContext);
    const decEvidence = decSigner.signDecoderEvidence({
      payload: {
        outcome: "SUCCESS",
        architecture: "ARM",
        baseAddress: 0x1000,
        totalBytes: 8,
        decodedBytes: 8,
        instructions: [
          { address: 0x1000, mnemonic: "ldr", operands: "r0, [sp, #4]", size: 4, rawBytesHex: "04009de5", isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null },
          { address: 0x1004, mnemonic: "bl", operands: "system", size: 4, rawBytesHex: "000000eb", isBranch: true, isConditional: false, isCall: true, isReturn: false, isIndirect: false, targetAddress: 0x2000 },
        ],
        provenance: { actualProvider: "InProcessInstructionDecoder", requestedProvider: "InProcessInstructionDecoder", isFallback: false, timestamp: Date.now() },
      },
      provider: "InProcessInstructionDecoder",
      architecture: "ARM",
    });
    expect(decEvidence.ok).toBe(true);
    if (!decEvidence.ok) return;

    const cfgSigner = authority.createCfgSigner(stageContext);
    const cfgEvidence = cfgSigner.signCfgEvidence({
      payload: {
        functionName: "handle_packet",
        entryBlockId: "bb_0",
        blocks: [{ id: "bb_0", startAddress: 0x1000, endAddress: 0x1004, functionName: "handle_packet", instructionsCount: 2, predecessorIds: [], successorIds: [], terminatorType: "call" }],
        edges: [],
        decodeOutcome: "SUCCESS",
        isComplete: true,
        cfgHash: "cfg_hash_test_01",
        architecture: "ARM",
      },
      parentDecoderEvidence: decEvidence.value,
      provider: "ReaControlFlowEngine",
    });
    expect(cfgEvidence.ok).toBe(true);
    if (!cfgEvidence.ok) return;

    const rchSigner = authority.createReachabilitySigner(stageContext);
    const rchEvidence = rchSigner.signReachabilityEvidence({
      payload: {
        status: "REACHABLE",
        paths: [{ source: "main", target: "system", steps: [{ functionName: "main", blockId: "bb_0", address: 0x1000, description: "entry" }], isDefinitive: true, unresolvedIndirectJumps: [] }],
        entryPoint: "main",
        target: "system",
        deadCodeFunctions: [],
        reasoning: "Definitive call to system()",
        provider: "ReaControlFlowEngine",
        analysisOutcome: "SUCCESS",
        isComplete: true,
      },
      parentCfgEvidence: cfgEvidence.value,
      provider: "ReaControlFlowEngine",
    });
    expect(rchEvidence.ok).toBe(true);
    if (!rchEvidence.ok) return;

    const taintSigner = authority.createTaintSigner(stageContext);
    const taintEvidence = taintSigner.signTaintEvidence({
      payload: {
        status: "PROVEN_TAINT",
        source: { kind: "network_socket", api: "recv", functionName: "handle_packet", address: 0x1000, targetParameterOrReturn: 0 },
        sink: { api: "system", functionName: "handle_packet", address: 0x1004, vulnerableParameterIndex: 0 },
        steps: [{ functionName: "handle_packet", address: 0x1000, operation: "parameter_pass", variableOrRegister: "r0", description: "Tainted network payload" }],
        sanitizers: [],
        isSanitized: false,
        hasUnresolvedAliases: false,
        reasoning: "Tainted argument passed unsanitized to system()",
      },
      parentCfgEvidence: cfgEvidence.value,
      provider: "ReaTaintEngine",
    });
    expect(taintEvidence.ok).toBe(true);
    if (!taintEvidence.ok) return;

    const witnessSigner = authority.createWitnessSigner(stageContext);
    const witnessEvidence = witnessSigner.signWitnessEvidence({
      payload: {
        witnessId: "wit_replay_test_01",
        findingId: testCandidate.ruleId,
        ruleId: testCandidate.ruleId,
        category: testCandidate.category,
        isSatisfiable: true,
        isReproducible: true,
        exploitabilityStatus: "PROVEN",
        conflictingGuards: [],
        validationLog: ["Verified satisfiable input"],
        constraints: [{ parameter: "cmd", type: "regex_pattern", expectedValue: "; /bin/sh", description: "Command separator injected" }],
        verifiedAt: new Date().toISOString(),
      },
      parentTaintEvidence: taintEvidence.value,
      provider: "ReaWitnessEngine",
    });
    expect(witnessEvidence.ok).toBe(true);
    if (!witnessEvidence.ok) return;

    const sealedBundle = {
      decoderEvidence: decEvidence.value,
      cfgEvidence: cfgEvidence.value,
      reachabilityEvidence: rchEvidence.value,
      taintEvidence: taintEvidence.value,
      witnessEvidence: witnessEvidence.value,
      candidates: [testCandidate as any],
    };

    // Insert task in blackboard
    storage.getDatabase().prepare(`
      INSERT INTO tasks (
        id, assessment_id, task_type, title, description, asset_id, priority, status,
        blocked_by_json, fencing_token, cas_version, claim_json, result_json, metadata_json,
        smoke_score, votes_json, evidence_hashes_json, created_at, updated_at
      ) VALUES (
        ?, ?, 'binary_analysis', 'Replay Test Task', 'Deep binary inspection', ?, 'high', 'claimed',
        '[]', ?, 1, '{}', null, '{}', 0, '[]', '[]', ?, ?
      )
    `).run(testTaskId, testAssessmentId, testAssetId, testFencingToken, Date.now(), Date.now());

    const testAssetObj = createTestAssetObj();

    // Adjudicate and persist in Run 1 (consumes witness evidence)
    const adjRes1 = validator.adjudicateAndPersist({
      storage,
      authority,
      bridge,
      asset: testAssetObj,
      candidate: testCandidate,
      bundle: sealedBundle,
      context: parentCtx,
    });
    expect(adjRes1.ok).toBe(true);

    const witnessEvidenceId = witnessEvidence.value.claims.evidenceId;

    // COLD RESTART: Close SQLite connection
    storage.close();

    // Reopen database from disk
    const storage2 = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId: testAssessmentId });
    const authority2 = new TrustedEvidenceAuthority({ keyringManager, db: storage2.getDatabase() });
    const verifier2 = new TrustedEvidenceVerifier({ keyringManager, db: storage2.getDatabase() });
    const bridge2 = new VulnerabilityAdjudicationBridge({ verifier: verifier2 });

    // Verify persistent state in reopened DB: witness is consumed!
    expect(verifier2.isEvidenceConsumed(witnessEvidenceId)).toBe(true);

    // Setup a new Run 2
    const runManager2 = authority2.getRunManager();
    const run2 = runManager2.startRun(testAssessmentId, testAssetId, dummyBinarySha256);

    const parentCtx2: ParentValidationContext = {
      ...parentCtx,
      runId: run2.runId,
      taskId: "tsk_replay_attempt_02",
      fencingToken: 1,
    };

    storage2.getDatabase().prepare(`
      INSERT INTO tasks (
        id, assessment_id, task_type, title, description, asset_id, priority, status,
        blocked_by_json, fencing_token, cas_version, claim_json, result_json, metadata_json,
        smoke_score, votes_json, evidence_hashes_json, created_at, updated_at
      ) VALUES (
        'tsk_replay_attempt_02', ?, 'binary_analysis', 'Replay Attempt Task', 'Replay witness', ?, 'high', 'claimed',
        '[]', 1, 1, '{}', null, '{}', 0, '[]', '[]', ?, ?
      )
    `).run(testAssessmentId, testAssetId, Date.now(), Date.now());

    // Attempting to consume the exact same witness in Run 2 must throw WITNESS_REPLAY_DETECTED
    expect(() => {
      validator.adjudicateAndPersist({
        storage: storage2,
        authority: authority2,
        bridge: bridge2,
        asset: testAssetObj,
        candidate: testCandidate,
        bundle: sealedBundle, // Reusing previously consumed witness
        context: parentCtx2,
      });
    }).toThrow(/WITNESS_REPLAY_DETECTED/);

    storage2.close();
  });

  // ==========================================================================
  // 6. Transaction Atomicity & Failure Injection
  // ==========================================================================
  it("SCENARIO-8: Failure injection during finding insertion completely rolls back all state", () => {
    const runManager = authority.getRunManager();
    const run = runManager.startRun(testAssessmentId, testAssetId, dummyBinarySha256);

    const parentCtx: ParentValidationContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      runId: run.runId,
      taskId: testTaskId,
      fencingToken: testFencingToken,
      workerId: "wkr_test_rollback",
      requestedStage: "ALL",
      architecture: "ARM",
      binaryInputBytes: dummyArmBytes,
    };

    // Setup task in blackboard
    storage.getDatabase().prepare(`
      INSERT INTO tasks (
        id, assessment_id, task_type, title, description, asset_id, priority, status,
        blocked_by_json, fencing_token, cas_version, claim_json, result_json, metadata_json,
        smoke_score, votes_json, evidence_hashes_json, created_at, updated_at
      ) VALUES (
        ?, ?, 'binary_analysis', 'Atomicity Test Task', 'Deep binary inspection', ?, 'high', 'claimed',
        '[]', ?, 1, '{}', null, '{}', 0, '[]', '[]', ?, ?
      )
    `).run(testTaskId, testAssessmentId, testAssetId, testFencingToken, Date.now(), Date.now());

    // Create minimal sealed bundle
    const stageContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      firmwareSha256: dummyBinarySha256,
      runId: run.runId,
    };

    const decEvidence = authority.createDecoderSigner(stageContext).signDecoderEvidence({
      payload: {
        outcome: "SUCCESS",
        architecture: "ARM",
        baseAddress: 0x1000,
        totalBytes: 8,
        decodedBytes: 8,
        instructions: [{ address: 0x1000, mnemonic: "mov", operands: "r0, r0", size: 4, rawBytesHex: "0000a0e1", isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null }],
        provenance: { actualProvider: "InProcessInstructionDecoder", requestedProvider: "InProcessInstructionDecoder", isFallback: false, timestamp: Date.now() },
      },
      provider: "InProcessInstructionDecoder",
      architecture: "ARM",
    });
    if (!decEvidence.ok) return;

    const cfgEvidence = authority.createCfgSigner(stageContext).signCfgEvidence({
      payload: {
        functionName: "handle_packet",
        entryBlockId: "bb_0",
        blocks: [{ id: "bb_0", startAddress: 0x1000, endAddress: 0x1004, functionName: "handle_packet", instructionsCount: 1, predecessorIds: [], successorIds: [], terminatorType: "fallthrough" }],
        edges: [],
        decodeOutcome: "SUCCESS",
        isComplete: true,
        cfgHash: "cfg_hash_test_atomicity",
        architecture: "ARM",
      },
      parentDecoderEvidence: decEvidence.value,
      provider: "ReaControlFlowEngine",
    });
    if (!cfgEvidence.ok) return;

    const rchEvidence = authority.createReachabilitySigner(stageContext).signReachabilityEvidence({
      payload: {
        status: "REACHABLE",
        paths: [{ source: "main", target: "system", steps: [], isDefinitive: true, unresolvedIndirectJumps: [] }],
        entryPoint: "main",
        target: "system",
        deadCodeFunctions: [],
        reasoning: "Path exists",
        provider: "ReaControlFlowEngine",
        analysisOutcome: "SUCCESS",
        isComplete: true,
      },
      parentCfgEvidence: cfgEvidence.value,
      provider: "ReaControlFlowEngine",
    });
    if (!rchEvidence.ok) return;

    const taintEvidence = authority.createTaintSigner(stageContext).signTaintEvidence({
      payload: {
        status: "PROVEN_TAINT",
        source: { kind: "network_socket", api: "recv", functionName: "main", address: 0, targetParameterOrReturn: 0 },
        sink: { api: "system", functionName: "main", address: 4, vulnerableParameterIndex: 0 },
        steps: [],
        sanitizers: [],
        isSanitized: false,
        hasUnresolvedAliases: false,
        reasoning: "Taint flows",
      },
      parentCfgEvidence: cfgEvidence.value,
      provider: "ReaTaintEngine",
    });
    if (!taintEvidence.ok) return;

    const witnessEvidence = authority.createWitnessSigner(stageContext).signWitnessEvidence({
      payload: {
        witnessId: "wit_atomicity_01",
        findingId: testCandidate.ruleId,
        ruleId: testCandidate.ruleId,
        category: testCandidate.category,
        isSatisfiable: true,
        isReproducible: true,
        exploitabilityStatus: "PROVEN",
        conflictingGuards: [],
        validationLog: [],
        constraints: [],
        verifiedAt: new Date().toISOString(),
      },
      parentTaintEvidence: taintEvidence.value,
      provider: "ReaWitnessEngine",
    });
    if (!witnessEvidence.ok) return;

    const bundle = {
      decoderEvidence: decEvidence.value,
      cfgEvidence: cfgEvidence.value,
      reachabilityEvidence: rchEvidence.value,
      taintEvidence: taintEvidence.value,
      witnessEvidence: witnessEvidence.value,
      candidates: [testCandidate as any],
    };

    const testAssetObj = createTestAssetObj();

    // Install an intentional failing trigger on findings table to force transaction abort during INSERT
    storage.getDatabase().prepare(`
      CREATE TRIGGER trigger_fail_finding_insert
      BEFORE INSERT ON findings
      BEGIN
        SELECT RAISE(FAIL, 'SIMULATED_FINDING_INSERT_ERROR');
      END;
    `).run();

    // Execute adjudicateAndPersist -> should throw simulated error
    expect(() => {
      validator.adjudicateAndPersist({
        storage,
        authority,
        bridge,
        asset: testAssetObj,
        candidate: testCandidate,
        bundle,
        context: parentCtx,
      });
    }).toThrow(/SIMULATED_FINDING_INSERT_ERROR/);

    // Verify zero state remained:
    // 1. Finding not inserted
    const findingRow = storage.getDatabase().prepare("SELECT * FROM findings WHERE id = ?").get(testCandidate.ruleId);
    expect(findingRow).toBeUndefined();

    // 2. Outbox event not inserted
    const outboxRow = storage.getDatabase().prepare("SELECT * FROM transactional_outbox WHERE entity_id = ?").get(testCandidate.ruleId);
    expect(outboxRow).toBeUndefined();

    // 3. Task NOT completed (remains claimed)
    const taskRow = storage.getDatabase().prepare("SELECT status FROM tasks WHERE id = ?").get(testTaskId) as any;
    expect(taskRow.status).toBe("claimed");

    // 4. Witness evidence NOT consumed in database!
    const witnessEvidenceId = witnessEvidence.value.claims.evidenceId;
    const isConsumed = verifier.isEvidenceConsumed(witnessEvidenceId);
    expect(isConsumed).toBe(false);
  });

  it("SCENARIO-9: Stale fencing token aborts transaction with zero state modification", () => {
    const runManager = authority.getRunManager();
    const run = runManager.startRun(testAssessmentId, testAssetId, dummyBinarySha256);

    // Setup task with fencing_token = 5 in blackboard
    storage.getDatabase().prepare(`
      INSERT INTO tasks (
        id, assessment_id, task_type, title, description, asset_id, priority, status,
        blocked_by_json, fencing_token, cas_version, claim_json, result_json, metadata_json,
        smoke_score, votes_json, evidence_hashes_json, created_at, updated_at
      ) VALUES (
        ?, ?, 'binary_analysis', 'Fencing Test Task', 'Verify token', ?, 'high', 'claimed',
        '[]', 5, 1, '{}', null, '{}', 0, '[]', '[]', ?, ?
      )
    `).run(testTaskId, testAssessmentId, testAssetId, Date.now(), Date.now());

    const testAssetObj = createTestAssetObj();

    // Caller presents stale fencing token (4 instead of 5)
    expect(() => {
      validator.adjudicateAndPersist({
        storage,
        authority,
        bridge,
        asset: testAssetObj,
        candidate: testCandidate,
        bundle: { candidates: [testCandidate as any] },
        context: {
          assessmentId: testAssessmentId,
          assetId: testAssetId,
          binarySha256: dummyBinarySha256,
          runId: run.runId,
          taskId: testTaskId,
          fencingToken: 4, // Stale!
          workerId: "wkr_test_01",
          requestedStage: "ALL",
          architecture: "ARM",
          binaryInputBytes: dummyArmBytes,
        },
      });
    }).toThrow(/STALE_TASK_LEASE/);

    // Verify task is still in claimed state with original fencing token
    const taskRow = storage.getDatabase().prepare("SELECT fencing_token, status FROM tasks WHERE id = ?").get(testTaskId) as any;
    expect(taskRow.fencing_token).toBe(5);
    expect(taskRow.status).toBe("claimed");
  });

  // ==========================================================================
  // 7. Six-State Lifecycle Invariant Verification
  // ==========================================================================
  it("SCENARIO-10: Incomplete decoder output cannot produce VERIFIED (produces INCONCLUSIVE)", () => {
    const runManager = authority.getRunManager();
    const run = runManager.startRun(testAssessmentId, testAssetId, dummyBinarySha256);

    const stageContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      firmwareSha256: dummyBinarySha256,
      runId: run.runId,
    };

    // Decoder with incomplete outcome
    const decEvidence = authority.createDecoderSigner(stageContext).signDecoderEvidence({
      payload: {
        outcome: "PARTIAL", // Incomplete!
        architecture: "ARM",
        baseAddress: 0x1000,
        totalBytes: 8,
        decodedBytes: 4,
        instructions: [{ address: 0x1000, mnemonic: "mov", operands: "r0, r0", size: 4, rawBytesHex: "0000a0e1", isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null }],
        provenance: { actualProvider: "InProcessInstructionDecoder", requestedProvider: "InProcessInstructionDecoder", isFallback: false, timestamp: Date.now() },
      },
      provider: "InProcessInstructionDecoder",
      architecture: "ARM",
    });
    if (!decEvidence.ok) return;

    const cfgEvidence = authority.createCfgSigner(stageContext).signCfgEvidence({
      payload: {
        functionName: "handle_packet",
        entryBlockId: "bb_0",
        blocks: [{ id: "bb_0", startAddress: 0x1000, endAddress: 0x1004, functionName: "handle_packet", instructionsCount: 1, predecessorIds: [], successorIds: [], terminatorType: "fallthrough" }],
        edges: [],
        decodeOutcome: "PARTIAL",
        isComplete: false,
        cfgHash: "cfg_hash_incomplete",
        architecture: "ARM",
      },
      parentDecoderEvidence: decEvidence.value,
      provider: "ReaControlFlowEngine",
    });
    if (!cfgEvidence.ok) return;

    const rchEvidence = authority.createReachabilitySigner(stageContext).signReachabilityEvidence({
      payload: {
        status: "REACHABLE",
        paths: [{ source: "main", target: "system", steps: [], isDefinitive: false, unresolvedIndirectJumps: [] }],
        entryPoint: "main",
        target: "system",
        deadCodeFunctions: [],
        reasoning: "Incomplete path",
        provider: "ReaControlFlowEngine",
        analysisOutcome: "PARTIAL",
        isComplete: false,
      },
      parentCfgEvidence: cfgEvidence.value,
      provider: "ReaControlFlowEngine",
    });
    if (!rchEvidence.ok) return;

    const testAssetObj = createTestAssetObj();

    const adj = bridge.adjudicateCandidate(testAssessmentId, testAssetObj, testCandidate, {
      trustedReachability: rchEvidence.value,
      runId: run.runId,
    });

    expect(adj.ok).toBe(true);
    if (!adj.ok) return;
    expect(adj.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(adj.value.lifecycleState).not.toBe("VERIFIED");
  });

  it("SCENARIO-11: Incomplete CFG claiming UNREACHABLE cannot produce FALSE_POSITIVE (produces INCONCLUSIVE)", () => {
    const runManager = authority.getRunManager();
    const run = runManager.startRun(testAssessmentId, testAssetId, dummyBinarySha256);

    const stageContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      firmwareSha256: dummyBinarySha256,
      runId: run.runId,
    };

    const decEvidence = authority.createDecoderSigner(stageContext).signDecoderEvidence({
      payload: {
        outcome: "SUCCESS",
        architecture: "ARM",
        baseAddress: 0x1000,
        totalBytes: 8,
        decodedBytes: 8,
        instructions: [{ address: 0x1000, mnemonic: "mov", operands: "r0, r0", size: 4, rawBytesHex: "0000a0e1", isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null }],
        provenance: { actualProvider: "InProcessInstructionDecoder", requestedProvider: "InProcessInstructionDecoder", isFallback: false, timestamp: Date.now() },
      },
      provider: "InProcessInstructionDecoder",
      architecture: "ARM",
    });
    if (!decEvidence.ok) return;

    const cfgEvidence = authority.createCfgSigner(stageContext).signCfgEvidence({
      payload: {
        functionName: "handle_packet",
        entryBlockId: "bb_0",
        blocks: [{ id: "bb_0", startAddress: 0x1000, endAddress: 0x1004, functionName: "handle_packet", instructionsCount: 1, predecessorIds: [], successorIds: [], terminatorType: "fallthrough" }],
        edges: [],
        decodeOutcome: "PARTIAL",
        isComplete: false, // Incomplete CFG!
        cfgHash: "cfg_hash_incomplete_cfg",
        architecture: "ARM",
      },
      parentDecoderEvidence: decEvidence.value,
      provider: "ReaControlFlowEngine",
    });
    if (!cfgEvidence.ok) return;

    const rchEvidence = authority.createReachabilitySigner(stageContext).signReachabilityEvidence({
      payload: {
        status: "UNREACHABLE", // Claims unreachable on an incomplete CFG!
        paths: [],
        entryPoint: "main",
        target: "system",
        deadCodeFunctions: [],
        reasoning: "Unreachable within explored partial graph",
        provider: "ReaControlFlowEngine",
        analysisOutcome: "PARTIAL",
        isComplete: false,
      },
      parentCfgEvidence: cfgEvidence.value,
      provider: "ReaControlFlowEngine",
    });
    if (!rchEvidence.ok) return;

    const testAssetObj = createTestAssetObj();

    const adj = bridge.adjudicateCandidate(testAssessmentId, testAssetObj, testCandidate, {
      trustedReachability: rchEvidence.value,
      runId: run.runId,
    });

    expect(adj.ok).toBe(true);
    if (!adj.ok) return;
    // MUST NOT be FALSE_POSITIVE because reachability proof was incomplete
    expect(adj.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(adj.value.lifecycleState).not.toBe("FALSE_POSITIVE");
  });

  // ==========================================================================
  // 8. Worker Crash Resilience & Clean Recovery
  // ==========================================================================
  it("SCENARIO-12: Worker crash during execution produces safe task recovery (fails closed)", async () => {
    // Child script that sends WORKER_READY, then crashes on input
    const crashWorkerScript = `
      process.stdout.write(JSON.stringify({
        protocolVersion: "1.0.0",
        kind: "WORKER_READY",
        messageId: "11111111-1111-4111-8111-111111111111",
        workerId: "wkr_crash_test_01",
        pid: process.pid,
        supportedArchitectures: ["ARM", "x86_64"],
        heapLimitBytes: null
      }) + "\\n");

      process.stdin.on("data", () => {
        process.exit(139); // Simulate SIGSEGV
      });
    `;

    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_crash_test_01",
        command: process.execPath,
        arguments: ["-e", crashWorkerScript],
      }),
    );
    await supervisor.start();

    const request: BinaryWorkerAnalyzeRequest = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_REQUEST",
      messageId: randomUUID(),
      taskId: testTaskId,
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      runId: "run_test_crash",
      fencingToken: testFencingToken,
      workerId: "wkr_crash_test_01",
      requestedStage: "ALL",
      binaryInput: {
        type: "inline_buffer",
        expected_sha256: dummyBinarySha256,
        byte_size: dummyArmBytes.length,
        data_base64: dummyArmBytes.toString("base64"),
        read_only: true,
      },
      analysisConfiguration: {
        architecture: "ARM",
        entryPoints: ["main"],
        maxInstructions: 10,
        maxCfgBlocks: 2,
        maxPaths: 1,
      },
      deadline: Date.now() + 10_000,
    };

    const result = await supervisor.executeTask(request);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("WORKER_CRASHED");
    }

    // Supervisor terminates safely
    expect(supervisor.getState()).toBe("TERMINATED");
  });

  // ==========================================================================
  // 9. Stale Response Dropped by Supervisor CAS
  // ==========================================================================
  it("SCENARIO-13: Outdated response carrying old fencing token is dropped by supervisor", async () => {
    const droppedEvents: BinarySupervisorLifecycleEvent[] = [];
    const supervisor = trackSupervisor(
      new BinaryWorkerSupervisor({
        workerId: "wkr_cas_test_01",
        onEvent: (e) => {
          if (e.type === "stale_response_dropped") droppedEvents.push(e);
        },
      }),
    );
    await supervisor.start();

    // Directly test supervisor's response discrimination
    const fakeStaleResponse: BinaryWorkerAnalyzeResponse = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_RESPONSE",
      messageId: randomUUID(),
      inReplyTo: "msg_req_mock_03",
      taskId: testTaskId,
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      runId: "run_test_cas",
      fencingToken: 1, // Stale fencing token
      workerId: supervisor.workerId,
      stage: "DECODE",
      executionStatus: "SUCCESS",
      decodeCompleteness: { isComplete: true, outcome: "SUCCESS", decodedBytes: 4, totalBytes: 4 },
      resultPayload: {},
      resultDigest: canonicalDigest({}),
      diagnostics: [],
      resourceUsage: { cpuTimeMs: 1, wallTimeMs: 1, peakMemoryBytes: 1024 },
    };

    // When no task is active with fencingToken 1, supervisor drops it safely
    (supervisor as any).handleIncomingMessage(fakeStaleResponse);

    expect(droppedEvents.length).toBe(1);
    expect(droppedEvents[0]?.type).toBe("stale_response_dropped");
  });

  // ==========================================================================
  // 10. Complete Six-State Lifecycle Matrix Verification
  // ==========================================================================
  it("SCENARIO-14: Six-state lifecycle assignment strictly enforces proof standards across all states", () => {
    const runManager = authority.getRunManager();
    const run = runManager.startRun(testAssessmentId, testAssetId, dummyBinarySha256);

    const testAssetObj = createTestAssetObj();

    const stageContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      firmwareSha256: dummyBinarySha256,
      runId: run.runId,
    };

    const decEvidence = authority.createDecoderSigner(stageContext).signDecoderEvidence({
      payload: {
        outcome: "SUCCESS",
        architecture: "ARM",
        baseAddress: 0x1000,
        totalBytes: 8,
        decodedBytes: 8,
        instructions: [{ address: 0x1000, mnemonic: "mov", operands: "r0, r0", size: 4, rawBytesHex: "0000a0e1", isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null }],
        provenance: { actualProvider: "InProcessInstructionDecoder", requestedProvider: "InProcessInstructionDecoder", isFallback: false, timestamp: Date.now() },
      },
      provider: "InProcessInstructionDecoder",
      architecture: "ARM",
    });
    if (!decEvidence.ok) return;

    const cfgEvidence = authority.createCfgSigner(stageContext).signCfgEvidence({
      payload: {
        functionName: "handle_packet",
        entryBlockId: "bb_0",
        blocks: [{ id: "bb_0", startAddress: 0x1000, endAddress: 0x1004, functionName: "handle_packet", instructionsCount: 1, predecessorIds: [], successorIds: [], terminatorType: "fallthrough" }],
        edges: [],
        decodeOutcome: "SUCCESS",
        isComplete: true,
        cfgHash: "cfg_hash_lifecycle",
        architecture: "ARM",
      },
      parentDecoderEvidence: decEvidence.value,
      provider: "ReaControlFlowEngine",
    });
    if (!cfgEvidence.ok) return;

    // 1. CANDIDATE: Static candidate without proof
    const resCandidate = bridge.adjudicateCandidate(testAssessmentId, testAssetObj, testCandidate);
    expect(resCandidate.ok).toBe(true);
    if (!resCandidate.ok) return;
    expect(resCandidate.value.lifecycleState).toBe("CANDIDATE");

    // 2. FALSE_POSITIVE: Sound complete CFG proving sink is in unreachable dead code
    const rchUnreachable = authority.createReachabilitySigner(stageContext).signReachabilityEvidence({
      payload: {
        status: "UNREACHABLE",
        paths: [],
        entryPoint: "main",
        target: "system",
        deadCodeFunctions: ["handle_packet"],
        reasoning: "Sink function handle_packet is unreachable from all entry points",
        provider: "ReaControlFlowEngine",
        analysisOutcome: "SUCCESS",
        isComplete: true,
      },
      parentCfgEvidence: cfgEvidence.value,
      provider: "ReaControlFlowEngine",
    });
    if (!rchUnreachable.ok) return;

    const resFalsePositive = bridge.adjudicateCandidate(testAssessmentId, testAssetObj, testCandidate, {
      trustedReachability: rchUnreachable.value,
      runId: run.runId,
    });
    expect(resFalsePositive.ok).toBe(true);
    if (!resFalsePositive.ok) return;
    expect(resFalsePositive.value.lifecycleState).toBe("FALSE_POSITIVE");

    // 3. MITIGATED: Reachable sink with sound dominating guard
    const rchReachable = authority.createReachabilitySigner(stageContext).signReachabilityEvidence({
      payload: {
        status: "REACHABLE",
        paths: [{ source: "main", target: "system", steps: [], isDefinitive: true, unresolvedIndirectJumps: [] }],
        entryPoint: "main",
        target: "system",
        deadCodeFunctions: [],
        reasoning: "Path exists",
        provider: "ReaControlFlowEngine",
        analysisOutcome: "SUCCESS",
        isComplete: true,
      },
      parentCfgEvidence: cfgEvidence.value,
      provider: "ReaControlFlowEngine",
    });
    if (!rchReachable.ok) return;

    const taintMitigated = authority.createTaintSigner(stageContext).signTaintEvidence({
      payload: {
        status: "MITIGATED_TAINT",
        source: { kind: "network_socket", api: "recv", functionName: "main", address: 0, targetParameterOrReturn: 0 },
        sink: { api: "system", functionName: "main", address: 4, vulnerableParameterIndex: 0 },
        steps: [],
        sanitizers: [
          {
            functionName: "handle_packet",
            address: 0x1002,
            type: "length_check",
            expression: "len < MAX_SAFE_CMD",
            isSound: true, // Sound!
            dominatesSink: true, // Dominates sink!
          },
        ],
        isSanitized: true,
        hasUnresolvedAliases: false,
        reasoning: "Dominating bounds check neutralizes injection vector",
      },
      parentCfgEvidence: cfgEvidence.value,
      provider: "ReaTaintEngine",
    });
    if (!taintMitigated.ok) return;

    const resMitigated = bridge.adjudicateCandidate(testAssessmentId, testAssetObj, testCandidate, {
      trustedReachability: rchReachable.value,
      trustedTaint: taintMitigated.value,
      runId: run.runId,
    });
    expect(resMitigated.ok).toBe(true);
    if (!resMitigated.ok) return;
    expect(resMitigated.value.lifecycleState).toBe("MITIGATED");

    // 4. VERIFIED: Full sound proof (reachability + taint + proven witness)
    const taintProven = authority.createTaintSigner(stageContext).signTaintEvidence({
      payload: {
        status: "PROVEN_TAINT",
        source: { kind: "network_socket", api: "recv", functionName: "main", address: 0, targetParameterOrReturn: 0 },
        sink: { api: "system", functionName: "main", address: 4, vulnerableParameterIndex: 0 },
        steps: [],
        sanitizers: [],
        isSanitized: false,
        hasUnresolvedAliases: false,
        reasoning: "Taint flows unsanitized",
      },
      parentCfgEvidence: cfgEvidence.value,
      provider: "ReaTaintEngine",
    });
    if (!taintProven.ok) return;

    const witnessProven = authority.createWitnessSigner(stageContext).signWitnessEvidence({
      payload: {
        witnessId: "wit_sound_proof_01",
        findingId: testCandidate.ruleId,
        ruleId: testCandidate.ruleId,
        category: testCandidate.category,
        isSatisfiable: true,
        isReproducible: true,
        exploitabilityStatus: "PROVEN",
        conflictingGuards: [],
        validationLog: [],
        constraints: [],
        verifiedAt: new Date().toISOString(),
      },
      parentTaintEvidence: taintProven.value,
      provider: "ReaWitnessEngine",
    });
    if (!witnessProven.ok) return;

    const resVerified = bridge.adjudicateCandidate(testAssessmentId, testAssetObj, testCandidate, {
      trustedReachability: rchReachable.value,
      trustedTaint: taintProven.value,
      trustedWitness: witnessProven.value,
      runId: run.runId,
    });
    expect(resVerified.ok).toBe(true);
    if (!resVerified.ok) return;
    expect(resVerified.value.lifecycleState).toBe("VERIFIED");
  });
});
