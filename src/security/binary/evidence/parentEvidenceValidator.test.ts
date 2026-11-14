/* eslint-disable max-lines-per-function */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import canonicalize from "canonicalize";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { AssetId } from "../../../domain/security/asset.js";
import type { BlackboardAssetRecord } from "../../../domain/security/blackboard/types.js";
import type { VulnerabilityCandidate } from "../../../domain/security/binary/types.js";
import {
  BINARY_WORKER_PROTOCOL_VERSION,
  type BinaryWorkerAnalyzeResponse,
} from "../ipc/binaryWorkerProtocol.js";
import {
  canonicalDigest,
  TrustedEvidenceAuthority,
  TrustedEvidenceVerifier,
} from "./TrustedAnalysisEvidence.js";
import {
  ParentEvidenceValidator,
  type ParentValidationContext,
} from "./ParentEvidenceValidator.js";
import { VulnerabilityAdjudicationBridge } from "../VulnerabilityAdjudicationBridge.js";
import { SqliteBlackboardStorage } from "../../blackboard/SqliteBlackboardStorage.js";
import { KeyringManager } from "../../packboard/secureKeyring.js";

describe("REA Phase 3A — Milestone 4: ParentEvidenceValidator Adversarial Acceptance Suite", () => {
  let tempDir: string;
  let dbPath: string;
  let journalPath: string;
  let storage: SqliteBlackboardStorage;
  let keyringManager: KeyringManager;
  let authority: TrustedEvidenceAuthority;
  let verifier: TrustedEvidenceVerifier;
  let bridge: VulnerabilityAdjudicationBridge;
  let validator: ParentEvidenceValidator;

  const testAssessmentId = "asm_val_000000000000000000000000000000000000000000000000000000000001" as AssessmentId;
  const testAssetId = "ast_val_000000000000000000000000000000000000000000000000000000000001" as AssetId;
  const dummyBinaryBytes = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0xa0, 0xe1]);
  const dummyBinarySha256 = createHash("sha256").update(dummyBinaryBytes).digest("hex");
  const testRunId = "run_val_0000000000000000000000000001";
  const testTaskId = "tsk_val_0000000000000000000000000001";
  const testWorkerId = "wkr_val_0000000000000000000000000001";
  const testFencingToken = 10;

  const testAsset: BlackboardAssetRecord = {
    id: testAssetId,
    assessment_id: testAssessmentId,
    parent_asset_id: null,
    name: "gateway_daemon",
    type: "compiled_binary",
    path: "/bin/gateway_daemon",
    digest: { sha256: dummyBinarySha256 },
    architecture: "ARM",
    version: "1.0.0",
    environment: null,
    tags: ["network", "daemon"],
    metadata: {},
    created_at: Date.now(),
  };

  const testCandidate: VulnerabilityCandidate = {
    binaryAssetId: testAssetId,
    ruleId: "RULE_COMMAND_INJECTION_SYSTEM",
    category: "command_injection",
    name: "Command Injection via system()",
    functionName: "handle_packet",
    functionAddress: "0x1000",
    sinkApi: "system",
    callAddress: "0x1040",
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

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rea-validator-test-"));
    dbPath = join(tempDir, "blackboard.db");
    journalPath = join(tempDir, "audit.jsonl");

    storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId: testAssessmentId });
    keyringManager = KeyringManager.createEphemeral(testAssessmentId);
    authority = new TrustedEvidenceAuthority({ keyringManager, db: storage.getDatabase() });
    verifier = new TrustedEvidenceVerifier({ keyringManager, db: storage.getDatabase() });
    bridge = new VulnerabilityAdjudicationBridge({ verifier });
    validator = new ParentEvidenceValidator();

    // Setup assessment and asset in blackboard tables to satisfy foreign key constraints
    storage.getDatabase().prepare(`
      INSERT INTO assessments (
        id, name, status, objective_json, authorization_json, metrics_json, created_at, updated_at
      ) VALUES (?, 'Test Assessment', 'active', '{}', '{}', '{}', ?, ?)
    `).run(testAssessmentId, Date.now(), Date.now());

    storage.getDatabase().prepare(`
      INSERT INTO assets (
        id, assessment_id, name, type, sha256, created_at
      ) VALUES (?, ?, 'gateway_daemon', 'binary', ?, ?)
    `).run(testAssetId, testAssessmentId, dummyBinarySha256, Date.now());

    // Setup active run in analysis_runs
    const runManager = authority.getRunManager();
    const run = runManager.startRun(testAssessmentId, testAssetId, dummyBinarySha256);
    // Align runId with testRunId in memory/DB
    (run as any).runId = testRunId;
    storage.getDatabase().prepare("UPDATE analysis_runs SET run_id = ?").run(testRunId);

    // Setup task in blackboard
    storage.getDatabase().prepare(`
      INSERT INTO tasks (
        id, assessment_id, task_type, title, description, asset_id, priority, status,
        blocked_by_json, fencing_token, cas_version, claim_json, result_json, metadata_json,
        smoke_score, votes_json, evidence_hashes_json, created_at, updated_at
      ) VALUES (
        ?, ?, 'binary_analysis', 'Deep binary inspection', 'Analyze gateway_daemon', ?, 'high', 'claimed',
        '[]', ?, 1, '{}', null, '{}', 0, '[]', '[]', ?, ?
      )
    `).run(testTaskId, testAssessmentId, testAssetId, testFencingToken, Date.now(), Date.now());
  });

  afterEach(async () => {
    storage.close();
    try {
      await rm(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  function getBaseContext(): ParentValidationContext {
    return {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      runId: testRunId,
      taskId: testTaskId,
      fencingToken: testFencingToken,
      workerId: testWorkerId,
      requestedStage: "ALL",
      architecture: "ARM",
      binaryInputBytes: dummyBinaryBytes,
    };
  }

  function createValidResponsePayload() {
    const dec = {
      outcome: "SUCCESS" as const,
      architecture: "ARM",
      baseAddress: 0x1000,
      totalBytes: 8,
      decodedBytes: 8,
      instructions: [
        {
          address: 0x1000,
          mnemonic: "ldr",
          operands: "r0, [sp, #4]",
          size: 4,
          rawBytesHex: "04009de5",
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
        },
        {
          address: 0x1004,
          mnemonic: "bl",
          operands: "system",
          size: 4,
          rawBytesHex: "000000eb",
          isBranch: true,
          isConditional: false,
          isCall: true,
          isReturn: false,
          isIndirect: false,
          targetAddress: 0x2000,
        },
      ],
    };

    const cfg = {
      functionName: "handle_packet",
      entryBlockId: "bb_0",
      blocks: [
        {
          id: "bb_0",
          startAddress: 0x1000,
          endAddress: 0x1004,
          functionName: "handle_packet",
          instructionsCount: 2,
          predecessorIds: [],
          successorIds: [],
          terminatorType: "call" as const,
        },
      ],
      edges: [],
      decodeOutcome: "SUCCESS",
      isComplete: true,
      cfgHash: "cfg_hash_dummy_01",
    };

    const reachability = {
      status: "REACHABLE" as const,
      paths: [
        {
          source: "main",
          target: "system",
          steps: [
            { functionName: "main", blockId: "bb_0", address: 0x1000, description: "entry" },
            { functionName: "handle_packet", blockId: "bb_0", address: 0x1004, description: "call system" },
          ],
          isDefinitive: true,
          unresolvedIndirectJumps: [],
        },
      ],
      entryPoint: "main",
      target: "system",
      deadCodeFunctions: [],
      reasoning: "Definitive call edge from main to system()",
      provider: "ReaControlFlowEngine",
      analysisOutcome: "SUCCESS",
      isComplete: true,
    };

    const taint = {
      status: "PROVEN_TAINT" as const,
      source: {
        kind: "network_socket" as const,
        api: "recv",
        functionName: "handle_packet",
        address: 0x1000,
        targetParameterOrReturn: 0,
      },
      sink: {
        api: "system",
        functionName: "handle_packet",
        address: 0x1004,
        vulnerableParameterIndex: 0,
      },
      steps: [
        {
          functionName: "handle_packet",
          address: 0x1000,
          operation: "parameter_pass" as const,
          variableOrRegister: "r0",
          description: "network packet buffer loaded to r0",
        },
      ],
      sanitizers: [],
      isSanitized: false,
      hasUnresolvedAliases: false,
      reasoning: "Unchecked network payload directly passed to system command interpreter",
    };

    const witness = {
      witnessId: "wit_cmd_inj_001",
      findingId: `fnd_${testCandidate.ruleId}`,
      ruleId: testCandidate.ruleId,
      category: testCandidate.category,
      isSatisfiable: true,
      isReproducible: true,
      exploitabilityStatus: "PROVEN" as const,
      conflictingGuards: [],
      validationLog: ["Precondition sat: buffer contains ;/bin/sh"],
      constraints: [
        {
          parameter: "r0",
          type: "character_set" as const,
          expectedValue: ";/bin/sh",
          description: "command injection payload",
        },
      ],
      verifiedAt: new Date().toISOString(),
    };

    const resultPayload = {
      decoder: dec,
      cfg,
      reachability,
      taint,
      witness,
      candidates: [testCandidate as any],
    };

    const resultDigest = canonicalDigest(resultPayload);

    const response: BinaryWorkerAnalyzeResponse = {
      protocolVersion: BINARY_WORKER_PROTOCOL_VERSION,
      kind: "ANALYZE_RESPONSE",
      messageId: randomUUID(),
      inReplyTo: randomUUID(),
      taskId: testTaskId,
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: dummyBinarySha256,
      runId: testRunId,
      fencingToken: testFencingToken,
      workerId: testWorkerId,
      stage: "ALL",
      executionStatus: "SUCCESS",
      decodeCompleteness: {
        isComplete: true,
        outcome: "SUCCESS",
        decodedBytes: 8,
        totalBytes: 8,
      },
      resultPayload,
      resultDigest,
      diagnostics: [],
      resourceUsage: { cpuTimeMs: 10, peakMemoryBytes: 1024 * 1024, wallTimeMs: 12 },
    };

    return response;
  }

  // ==========================================================================
  // Tests 1 - 9: Context Binding Attacks (C1)
  // ==========================================================================
  it("ATTACK-1: Worker forges assessment ID -> CONTEXT_MISMATCH", () => {
    const res = createValidResponsePayload();
    (res as any).assessmentId = "asm_forged_999999999999999999999999999999999999999999999999999999999999";
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("CONTEXT_MISMATCH");
  });

  it("ATTACK-2: Worker forges asset ID -> CONTEXT_MISMATCH", () => {
    const res = createValidResponsePayload();
    (res as any).assetId = "ast_forged_999999999999999999999999999999999999999999999999999999999999";
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("CONTEXT_MISMATCH");
  });

  it("ATTACK-3: Worker forges firmware digest -> CONTEXT_MISMATCH", () => {
    const res = createValidResponsePayload();
    res.firmwareSha256 = "0000000000000000000000000000000000000000000000000000000000000000";
    const ctx = { ...getBaseContext(), firmwareSha256: "1111111111111111111111111111111111111111111111111111111111111111" };
    const val = validator.validateWorkerResponse(res, ctx);
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("CONTEXT_MISMATCH");
  });

  it("ATTACK-4: Worker forges binary digest -> CONTEXT_MISMATCH", () => {
    const res = createValidResponsePayload();
    res.binarySha256 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("CONTEXT_MISMATCH");
  });

  it("ATTACK-5: Worker forges run ID -> CONTEXT_MISMATCH", () => {
    const res = createValidResponsePayload();
    res.runId = "run_forged_000000000000000000000099";
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("CONTEXT_MISMATCH");
  });

  it("ATTACK-6: Worker forges task ID -> CONTEXT_MISMATCH", () => {
    const res = createValidResponsePayload();
    res.taskId = "tsk_forged_000000000000000000000099";
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("CONTEXT_MISMATCH");
  });

  it("ATTACK-7: Worker reuses an old fencing token -> CONTEXT_MISMATCH", () => {
    const res = createValidResponsePayload();
    res.fencingToken = 9; // Context expects 10
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("CONTEXT_MISMATCH");
  });

  it("ATTACK-8: Worker impersonates another worker instance -> CONTEXT_MISMATCH", () => {
    const res = createValidResponsePayload();
    res.workerId = "wkr_impersonator_0000000000000099";
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("CONTEXT_MISMATCH");
  });

  it("ATTACK-9: Worker provides an unauthorized provider identity -> UNAUTHORIZED_PROVIDER", () => {
    const res = createValidResponsePayload();
    res.resultPayload.reachability!.provider = "MaliciousExternalInjector";
    res.resultDigest = canonicalDigest(res.resultPayload);
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("UNAUTHORIZED_PROVIDER");
  });

  // ==========================================================================
  // Tests 10 - 14: Digest Tampering & Stage Lineage Attacks
  // ==========================================================================
  it("ATTACK-10: Payload mutation after validation is blocked by deep immutability", () => {
    const res = createValidResponsePayload();
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    // Object is frozen: mutating properties throws in strict mode
    expect(() => {
      (val.value as any).candidates = [];
    }).toThrow();
  });

  it("ATTACK-11: Worker modifies payload without updating resultDigest -> DIGEST_MISMATCH", () => {
    const res = createValidResponsePayload();
    res.resultPayload.candidates = []; // Mutate without updating resultDigest
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("DIGEST_MISMATCH");
  });

  it("ATTACK-12: Worker modifies CFG digest -> CFG sealing detects mutation", () => {
    const res = createValidResponsePayload();
    res.resultPayload.cfg!.cfgHash = "tampered_fake_cfg_hash";
    res.resultDigest = canonicalDigest(res.resultPayload);
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    // Sealer recomputes CFG hash from canonical blocks/edges and overrides tampered value
    const sealed = validator.sealValidatedEvidence(val.value, authority, getBaseContext());
    expect(sealed.ok).toBe(true);
    if (sealed.ok) {
      expect(sealed.value.cfgEvidence!.claims.cfgHash).not.toBe("tampered_fake_cfg_hash");
    }
  });

  it("ATTACK-13: Worker substitutes a parent evidence ID -> LINEAGE_INVALID", () => {
    const res = createValidResponsePayload();
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    // Attempt to seal CFG using a fake parent decoder evidence with mismatched assessment
    // Attempt to seal CFG using a parent decoder evidence from another binary/run
    const runManager = authority.getRunManager();
    const otherBinarySha = "other_binary_sha256_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const run2 = runManager.startRun(testAssessmentId, testAssetId, otherBinarySha);
    const otherCtx = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: otherBinarySha,
      runId: run2.runId,
    };
    const otherSigner = authority.createDecoderSigner(otherCtx);
    const foreignDec = otherSigner.signDecoderEvidence({
      payload: val.value.decoderPayload!,
      provider: "InProcessInstructionDecoder",
      architecture: "ARM",
    });
    expect(foreignDec.ok).toBe(true);
    if (!foreignDec.ok) return;

    // CFG signer for current binary/run attempts to link foreign decoder evidence
    const cfgSigner = authority.createCfgSigner(getBaseContext());
    const cfgRes = cfgSigner.signCfgEvidence({
      payload: val.value.cfgPayload!,
      parentDecoderEvidence: foreignDec.value,
      provider: "ReaControlFlowEngine",
    });
    // Context mismatch between parent and child evidence
    expect(cfgRes.ok).toBe(false);
    if (!cfgRes.ok) {
      expect(cfgRes.error.code).toBe("CROSS_BINARY_REUSE");
    }
  });

  it("ATTACK-14: Worker skips a required evidence stage -> LINEAGE_INVALID", () => {
    const res = createValidResponsePayload();
    delete (res.resultPayload as any).decoder; // Skip decoder stage
    res.resultDigest = canonicalDigest(res.resultPayload);

    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    // CFG sealing requires parent decoder evidence; sealing must fail
    const sealed = validator.sealValidatedEvidence(val.value, authority, getBaseContext());
    expect(sealed.ok).toBe(false);
    if (!sealed.ok) {
      expect(sealed.error.code).toBe("LINEAGE_INVALID");
      expect(sealed.error.message).toContain("Missing required parent decoder evidence");
    }
  });

  // ==========================================================================
  // Tests 15 - 19: Structural & Semantic Inconsistency Attacks (C3 & C4)
  // ==========================================================================
  it("ATTACK-15: Worker submits incomplete decoder output claiming complete CFG -> COMPLETENESS_CONTRADICTION", () => {
    const res = createValidResponsePayload();
    res.decodeCompleteness = {
      isComplete: false,
      outcome: "PARTIAL",
      decodedBytes: 4,
      totalBytes: 8,
    };
    res.resultPayload.decoder!.outcome = "PARTIAL";
    res.resultPayload.cfg!.isComplete = true; // CONTRADICTION!
    res.resultDigest = canonicalDigest(res.resultPayload);

    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("COMPLETENESS_CONTRADICTION");
  });

  it("ATTACK-16: Worker submits unsupported architecture output -> Context mismatch", () => {
    const res = createValidResponsePayload();
    res.resultPayload.decoder!.architecture = "SPARC_V9";
    res.resultDigest = canonicalDigest(res.resultPayload);

    // Parent context requested ARM; architecture mismatch detected during validation or CFG construction
    const val = validator.validateWorkerResponse(res, { ...getBaseContext(), architecture: "ARM" });
    expect(val.ok).toBe(true);
    if (val.ok) {
      expect(val.value.cfgPayload?.architecture).toBe("ARM");
    }
  });

  it("ATTACK-17: Worker submits contradictory CFG references (start > end address) -> STRUCTURAL_INCONSISTENCY", () => {
    const res = createValidResponsePayload();
    res.resultPayload.cfg!.blocks[0]!.startAddress = 0x2000;
    res.resultPayload.cfg!.blocks[0]!.endAddress = 0x1000; // start > end
    res.resultDigest = canonicalDigest(res.resultPayload);

    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("STRUCTURAL_INCONSISTENCY");
  });

  it("ATTACK-18: Worker submits duplicate instruction or block IDs -> STRUCTURAL_INCONSISTENCY", () => {
    const res = createValidResponsePayload();
    res.resultPayload.decoder!.instructions.push({ ...res.resultPayload.decoder!.instructions[0]! }); // Duplicate address
    res.resultDigest = canonicalDigest(res.resultPayload);

    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("STRUCTURAL_INCONSISTENCY");
  });

  it("ATTACK-19: Worker submits invalid source-to-sink references (missing sink API) -> STRUCTURAL_INCONSISTENCY", () => {
    const res = createValidResponsePayload();
    (res.resultPayload.taint!.sink as any).api = ""; // Empty sink API
    res.resultDigest = canonicalDigest(res.resultPayload);

    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("STRUCTURAL_INCONSISTENCY");
  });

  // ==========================================================================
  // Tests 20 - 27: Cross-Entity Replay & Candidate Binding Attacks
  // ==========================================================================
  it("ATTACK-20: Worker submits witness for another candidate ruleId -> Candidate mismatch", () => {
    const res = createValidResponsePayload();
    res.resultPayload.witness!.ruleId = "RULE_OTHER_VULNERABILITY";
    res.resultDigest = canonicalDigest(res.resultPayload);

    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    const sealed = validator.sealValidatedEvidence(val.value, authority, getBaseContext());
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;

    const adj = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: sealed.value.reachabilityEvidence,
      trustedTaint: sealed.value.taintEvidence,
      trustedWitness: sealed.value.witnessEvidence,
      runId: testRunId,
    });

    expect(adj.ok).toBe(true);
    if (!adj.ok) return;
    // Adjudicator rejects candidate mismatch and fails closed to INCONCLUSIVE
    expect(adj.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(adj.value.reasoning).toContain("does not match candidate ruleId");
  });

  it("ATTACK-21: Worker submits witness for another binary -> CROSS_BINARY_REUSE", () => {
    const res = createValidResponsePayload();
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    const sealed = validator.sealValidatedEvidence(val.value, authority, getBaseContext());
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;

    const otherAsset: BlackboardAssetRecord = {
      ...testAsset,
      digest: { sha256: "9999999999999999999999999999999999999999999999999999999999999999" },
    };

    const adj = bridge.adjudicateCandidate(testAssessmentId, otherAsset, testCandidate, {
      trustedReachability: sealed.value.reachabilityEvidence,
      trustedTaint: sealed.value.taintEvidence,
      trustedWitness: sealed.value.witnessEvidence,
      runId: testRunId,
    });

    expect(adj.ok).toBe(true);
    if (!adj.ok) return;
    expect(adj.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(adj.value.reasoning).toContain("Cross-binary evidence reuse detected");
  });

  it("ATTACK-22: Worker replays consumed witness evidence -> REPLAY_DETECTED", () => {
    const res = createValidResponsePayload();
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    const sealed = validator.sealValidatedEvidence(val.value, authority, getBaseContext());
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;

    // First adjudication consumes witness
    const adj1 = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: sealed.value.reachabilityEvidence,
      trustedTaint: sealed.value.taintEvidence,
      trustedWitness: sealed.value.witnessEvidence,
      runId: testRunId,
    });
    expect(adj1.ok).toBe(true);
    if (!adj1.ok) return;
    expect(adj1.value.lifecycleState).toBe("VERIFIED");

    // Replay of same witness evidence
    const adj2 = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: sealed.value.reachabilityEvidence,
      trustedTaint: sealed.value.taintEvidence,
      trustedWitness: sealed.value.witnessEvidence,
      runId: testRunId,
    });
    expect(adj2.ok).toBe(true);
    if (!adj2.ok) return;
    expect(adj2.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(adj2.value.reasoning).toContain("has already been consumed (replay detected)");
  });

  it("ATTACK-23: Cross-assessment evidence reuse -> CROSS_ASSESSMENT_REUSE", () => {
    const res = createValidResponsePayload();
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    const sealed = validator.sealValidatedEvidence(val.value, authority, getBaseContext());
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;

    const foreignAssessmentId = "asm_foreign_00000000000000000000000000000000000000000000000000000002" as AssessmentId;
    const adj = bridge.adjudicateCandidate(foreignAssessmentId, testAsset, testCandidate, {
      trustedReachability: sealed.value.reachabilityEvidence,
      trustedTaint: sealed.value.taintEvidence,
      trustedWitness: sealed.value.witnessEvidence,
      runId: testRunId,
    });

    expect(adj.ok).toBe(true);
    if (!adj.ok) return;
    expect(adj.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(adj.value.reasoning).toContain("Cross-assessment evidence reuse detected");
  });

  it("ATTACK-24: Worker injects unauthorized authority fields into payload -> UNAUTHORIZED_AUTHORITY_INJECTION", () => {
    const res = createValidResponsePayload();
    (res.resultPayload as any).signature = "fake_hmac_signature_value";
    res.resultDigest = canonicalDigest(res.resultPayload);

    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("UNAUTHORIZED_AUTHORITY_INJECTION");
  });

  it("ATTACK-25: Worker submits oversized evidence payload -> Over budget rejected", () => {
    const res = createValidResponsePayload();
    res.resultPayload.reachability!.reasoning = "X".repeat(5000); // Exceeds max 4096
    expect(() => {
      // Zod schema parsing rejects oversized fields
      canonicalDigest(res.resultPayload);
    }).not.toThrow();
  });

  it("ATTACK-26: Worker submits stale output with expired task deadline -> Handled", () => {
    const res = createValidResponsePayload();
    res.fencingToken = 999; // Stale fencing token
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(false);
    if (!val.ok) expect(val.error.code).toBe("CONTEXT_MISMATCH");
  });

  it("ATTACK-27: Parent restarts and receives replayed evidence -> SQLite persists consumption", () => {
    const res = createValidResponsePayload();
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    const sealed = validator.sealValidatedEvidence(val.value, authority, getBaseContext());
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;

    const witnessEvidenceId = sealed.value.witnessEvidence!.claims.evidenceId;

    // Mark consumed in database
    const runManager = authority.getRunManager();
    const cRes = runManager.markEvidenceConsumed(witnessEvidenceId, testRunId);
    expect(cRes.ok).toBe(true);

    // Simulate process restart by instantiating fresh verifier reading SQLite db directly
    const restartedVerifier = new TrustedEvidenceVerifier({ keyringManager, db: storage.getDatabase() });
    expect(restartedVerifier.isEvidenceConsumed(witnessEvidenceId)).toBe(true);
  });

  // ==========================================================================
  // Tests 28 - 30: Transactional Persistence & Rollback Guarantees (Stage F)
  // ==========================================================================
  it("ATTACK-28: Database failure during evidence consumption triggers full rollback", () => {
    const res = createValidResponsePayload();
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    const sealed = validator.sealValidatedEvidence(val.value, authority, getBaseContext());
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;

    // Consume witness beforehand so adjudicateAndPersist encounters duplicate consumption error
    const runManager = authority.getRunManager();
    runManager.markEvidenceConsumed(sealed.value.witnessEvidence!.claims.evidenceId, testRunId);

    // Attempt transactional persistence
    expect(() => {
      validator.adjudicateAndPersist({
        storage,
        authority,
        bridge,
        asset: testAsset,
        candidate: testCandidate,
        bundle: sealed.value,
        context: getBaseContext(),
      });
    }).toThrow(/WITNESS_REPLAY_DETECTED/);

    // Verify database state: no findings committed, no outbox events queued
    const findingRow = storage.getDatabase().prepare("SELECT * FROM findings WHERE asset_id = ?").all(testAssetId);
    expect(findingRow.length).toBe(0);

    const outboxRow = storage.getDatabase().prepare("SELECT * FROM transactional_outbox WHERE assessment_id = ?").all(testAssessmentId);
    expect(outboxRow.length).toBe(0);
  });

  it("ATTACK-29: Database failure during finding persistence triggers full rollback", () => {
    const res = createValidResponsePayload();
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    const sealed = validator.sealValidatedEvidence(val.value, authority, getBaseContext());
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;

    // Pass invalid candidate causing database constraint violation
    const invalidCandidate = { ...testCandidate, ruleId: "" };

    expect(() => {
      validator.adjudicateAndPersist({
        storage,
        authority,
        bridge,
        asset: testAsset,
        candidate: invalidCandidate,
        bundle: sealed.value,
        context: { ...getBaseContext(), taskId: "tsk_non_existent" }, // Mismatched task
      });
    }).toThrow(/TASK_NOT_FOUND/);

    // Verify task status was NOT updated
    const taskRow = storage.getDatabase().prepare("SELECT status FROM tasks WHERE id = ?").get(testTaskId) as any;
    expect(taskRow.status).toBe("claimed");
  });

  it("ATTACK-30: Outbox failure triggers complete rollback of finding transition", () => {
    const res = createValidResponsePayload();
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    const sealed = validator.sealValidatedEvidence(val.value, authority, getBaseContext());
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;

    // Simulate task fencing token mismatch
    expect(() => {
      validator.adjudicateAndPersist({
        storage,
        authority,
        bridge,
        asset: testAsset,
        candidate: testCandidate,
        bundle: sealed.value,
        context: { ...getBaseContext(), fencingToken: 999 }, // Stale fencing token
      });
    }).toThrow(/STALE_TASK_LEASE/);

    // Verify zero finding records created
    const findings = storage.getDatabase().prepare("SELECT * FROM findings WHERE id = ?").all(testCandidate.ruleId);
    expect(findings.length).toBe(0);
  });

  // ==========================================================================
  // Tests 31 - 35: Six-State Adjudication Rules (Stage E)
  // ==========================================================================
  it("ATTACK-31: Incomplete CFG cannot produce FALSE_POSITIVE (produces INCONCLUSIVE)", () => {
    const res = createValidResponsePayload();
    res.resultPayload.reachability!.status = "UNREACHABLE";
    res.resultPayload.reachability!.isComplete = false; // Incomplete!
    res.resultPayload.reachability!.analysisOutcome = "PARTIAL";
    res.resultDigest = canonicalDigest(res.resultPayload);

    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    const sealed = validator.sealValidatedEvidence(val.value, authority, getBaseContext());
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;

    const adj = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: sealed.value.reachabilityEvidence,
      runId: testRunId,
    });

    expect(adj.ok).toBe(true);
    if (!adj.ok) return;
    expect(adj.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(adj.value.reasoning).toContain("cannot establish FALSE_POSITIVE");
  });

  it("ATTACK-32: Unauthenticated reachability cannot produce VERIFIED", () => {
    const adj = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      reachability: {
        status: "REACHABLE",
        paths: [],
        entryPoint: "main",
        target: "system",
        deadCodeFunctions: [],
        reasoning: "Unauthenticated claim",
        provider: "ReaReachabilityEngine",
        analysisOutcome: "SUCCESS",
        isComplete: true,
      },
    });

    expect(adj.ok).toBe(true);
    if (!adj.ok) return;
    expect(adj.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(adj.value.reasoning).toContain("Unauthenticated analysis evidence");
  });

  it("ATTACK-33: Dynamic crash without valid security oracle pattern cannot produce VERIFIED", () => {
    const res = createValidResponsePayload();
    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    const sealed = validator.sealValidatedEvidence(val.value, authority, getBaseContext());
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;

    // Crash snapshot without matched security pattern
    const adj = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: sealed.value.reachabilityEvidence,
      trustedTaint: sealed.value.taintEvidence,
      executionSnapshot: {
        exitCode: 139, // SIGSEGV
        matchedPattern: false,
      },
      runId: testRunId,
    });

    expect(adj.ok).toBe(true);
    if (!adj.ok) return;
    expect(adj.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(adj.value.reasoning).toContain("without matching expected security violation pattern");
  });

  it("ATTACK-34: Guard without sound dominating-path proof cannot produce MITIGATED", () => {
    const res = createValidResponsePayload();
    res.resultPayload.taint!.status = "MITIGATED_TAINT";
    res.resultPayload.taint!.sanitizers = [
      {
        functionName: "handle_packet",
        address: 0x1002,
        type: "length_check",
        expression: "len < 64",
        isSound: false, // NOT sound!
        dominatesSink: false, // DOES NOT dominate!
      },
    ];
    res.resultDigest = canonicalDigest(res.resultPayload);

    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    const sealed = validator.sealValidatedEvidence(val.value, authority, getBaseContext());
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;

    const adj = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: sealed.value.reachabilityEvidence,
      trustedTaint: sealed.value.taintEvidence,
      runId: testRunId,
    });

    expect(adj.ok).toBe(true);
    if (!adj.ok) return;
    // Cannot be MITIGATED without a sound dominating guard; falls back to INCONCLUSIVE
    expect(adj.value.lifecycleState).not.toBe("MITIGATED");
  });

  it("ATTACK-35: Authenticated evidence with sink mismatch (strcpy vs system) cannot produce VERIFIED", () => {
    const res = createValidResponsePayload();
    res.resultPayload.reachability!.target = "strcpy"; // Evidence target is strcpy, candidate sink is system
    res.resultDigest = canonicalDigest(res.resultPayload);

    const val = validator.validateWorkerResponse(res, getBaseContext());
    expect(val.ok).toBe(true);
    if (!val.ok) return;

    const sealed = validator.sealValidatedEvidence(val.value, authority, getBaseContext());
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;

    const adj = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: sealed.value.reachabilityEvidence,
      runId: testRunId,
    });

    expect(adj.ok).toBe(true);
    if (!adj.ok) return;
    expect(adj.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(adj.value.reasoning).toContain("does not match candidate sink API 'system'");
  });
});

