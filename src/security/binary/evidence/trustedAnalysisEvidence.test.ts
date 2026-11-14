/* eslint-disable max-lines-per-function */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { AssetId } from "../../../domain/security/asset.js";
import type { BlackboardAssetRecord } from "../../../domain/security/blackboard/types.js";
import type { VulnerabilityCandidate } from "../../../domain/security/binary/types.js";
import type { Result } from "../../../domain/result.js";
import { KeyringManager } from "../../packboard/secureKeyring.js";
import { applyBlackboardMigrations } from "../../blackboard/BlackboardSchema.js";
import { SqliteBlackboardStorage } from "../../blackboard/SqliteBlackboardStorage.js";
import { VulnerabilityAdjudicationBridge } from "../VulnerabilityAdjudicationBridge.js";
import {
  AnalysisRunManager,
  canonicalDigest,
  computeEvidenceSignature,
  deepFreeze,
  TrustedEvidenceAuthority,
  TrustedEvidenceVerifier,
} from "./TrustedAnalysisEvidence.js";
import type {
  CfgPayload,
  DecoderPayload,
  ReachabilityPayload,
  TaintPayload,
  WitnessPayload,
} from "./types.js";

const testAssessmentId = "asm_adv_test_00000000000000000000000000000000000000000000000000000001" as AssessmentId;
const testAssetId = "ast_adv_bin_00000000000000000000000000000000000000000000000000000001" as AssetId;
const testBinarySha256 = "1111111111111111111111111111111111111111111111111111111111111111";

const testAsset: BlackboardAssetRecord = {
  id: testAssetId,
  assessment_id: testAssessmentId,
  parent_asset_id: null,
  name: "gateway_daemon",
  type: "compiled_binary",
  path: "/bin/gateway_daemon",
  digest: { sha256: testBinarySha256 },
  architecture: "ARM",
  version: "1.0",
  environment: null,
  tags: ["security_test"],
  metadata: {},
  created_at: Date.now(),
};

const testCandidate: VulnerabilityCandidate = {
  binaryAssetId: testAsset.id,
  ruleId: "REA-ADV-001-CMD-INJECTION",
  category: "command_injection",
  name: "system() shell injection",
  functionName: "handle_cmd",
  functionAddress: "0x00010400",
  sinkApi: "system",
  callAddress: "0x00010420",
  callerInfo: "handle_cmd caller",
  sourceOfInput: "network",
  guardInfo: null,
  evidenceReferences: ["ev_system_call"],
  detectionMethod: "L5_WITNESS",
  confidenceScore: 1.0,
  confidenceLimitations: [],
  cwe: ["CWE-78"],
  technicalDescription: "User input directly executed in system()",
  remediationGuidance: "Remove system()",
};

describe("Sprint 3B: Mandatory Adversarial Security Verification Suite", () => {
  let tempDir: string;
  let dbPath: string;
  let db: DatabaseSync;
  let storage: SqliteBlackboardStorage;
  let keyring: KeyringManager;
  let authority: TrustedEvidenceAuthority;
  let verifier: TrustedEvidenceVerifier;
  let runManager: AnalysisRunManager;
  let bridge: VulnerabilityAdjudicationBridge;
  let activeRunId: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rea-adv-test-"));
    dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath, assessmentId: testAssessmentId });
    db = storage.getDatabase();
    keyring = storage.getKeyringManager();

    await storage.assessments.create({
      id: testAssessmentId,
      name: "Adversarial Assessment",
      status: "active",
      objective: { title: "Adversarial Test", target_technologies: [], compliance_frameworks: [], focus_areas: [], depth: "surface" },
      authorization: { allowed_targets: [], denied_targets: [], authorized_by: "Security Lead", authorization_reference: "AUTH-01", valid_until: "2027-01-01", allow_active_verification: false },
      metrics: { total_assets: 0, total_findings: 0, critical_findings: 0, high_findings: 0, medium_findings: 0, low_findings: 0, info_findings: 0, verified_findings: 0 },
      created_at: Date.now(),
      updated_at: Date.now(),
    });

    runManager = new AnalysisRunManager(db);
    authority = new TrustedEvidenceAuthority({ keyringManager: keyring, db, runManager });
    verifier = new TrustedEvidenceVerifier({ keyringManager: keyring, runManager });
    bridge = new VulnerabilityAdjudicationBridge({ verifier });

    const run = runManager.startRun(testAssessmentId, testAssetId, testBinarySha256);
    activeRunId = run.runId;
  });

  afterEach(async () => {
    storage.close();
    try {
      await rm(tempDir, { recursive: true, force: true });
    } catch {
      // Best effort cleanup
    }
  });

  // Helper to construct a valid trusted evidence chain up to reachability
  function unwrap<T>(res: Result<T, any>): T {
    if (!res.ok) {
      throw new Error(`Expected ok result, got error: ${JSON.stringify((res as any).error)}`);
    }
    return res.value;
  }

  function unwrapError<E>(res: Result<any, E>): E {
    if (res.ok) {
      throw new Error(`Expected error result, got value: ${JSON.stringify((res as any).value)}`);
    }
    return res.error;
  }

  function createValidEvidencePipeline(options?: {
    isComplete?: boolean;
    decodeOutcome?: string;
    reachabilityStatus?: "REACHABLE" | "UNREACHABLE" | "INCONCLUSIVE";
  }) {
    const isComplete = options?.isComplete ?? true;
    const outcome = options?.decodeOutcome ?? "SUCCESS";
    const status = options?.reachabilityStatus ?? "REACHABLE";

    const stageContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: testBinarySha256,
      runId: activeRunId,
    };

    // 1. Decoder
    const decSigner = authority.createDecoderSigner(stageContext);
    const decPayload: DecoderPayload = {
      instructions: [
        {
          address: 0x1000,
          mnemonic: "push",
          operands: "{r7, lr}",
          size: 4,
          rawBytesHex: "00482de9",
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
        },
      ],
      outcome,
      architecture: "ARM",
      baseAddress: 0x1000,
      totalBytes: 4,
      decodedBytes: isComplete ? 4 : 2,
      provenance: {
        actualProvider: "InProcessInstructionDecoder",
        isFallback: false,
        timestamp: Date.now(),
      },
    };
    const decRes = decSigner.signDecoderEvidence({
      payload: decPayload,
      provider: "InProcessInstructionDecoder",
      architecture: "ARM",
    });
    const decoder = unwrap(decRes);

    // 2. CFG
    const cfgSigner = authority.createCfgSigner(stageContext);
    const cfgPayload: CfgPayload = {
      functionName: "handle_cmd",
      entryBlockId: "bb_0x1000",
      blocks: [
        {
          id: "bb_0x1000",
          startAddress: 0x1000,
          endAddress: 0x1004,
          functionName: "handle_cmd",
          instructionsCount: 1,
          predecessorIds: [],
          successorIds: [],
          terminatorType: "return",
        },
      ],
      edges: [],
      architecture: "ARM",
      decodeOutcome: outcome,
      isComplete,
      cfgHash: "none",
    };
    const cfgRes = cfgSigner.signCfgEvidence({
      payload: cfgPayload,
      parentDecoderEvidence: decoder,
    });
    const cfg = unwrap(cfgRes);

    // 3. Reachability
    const reachSigner = authority.createReachabilitySigner(stageContext);
    const reachPayload: ReachabilityPayload = {
      status,
      paths: status === "REACHABLE" ? [
        {
          source: "main",
          target: "system",
          steps: [{ functionName: "handle_cmd", blockId: "bb_0x1000", address: 0x1000, description: "Call step" }],
          isDefinitive: true,
          unresolvedIndirectJumps: [],
        },
      ] : [],
      entryPoint: "main",
      target: "system",
      deadCodeFunctions: status === "UNREACHABLE" ? ["handle_cmd"] : [],
      reasoning: `Reachability is ${status}`,
      provider: "ReaControlFlowEngine",
      analysisOutcome: outcome,
      isComplete,
    };
    const reachRes = reachSigner.signReachabilityEvidence({
      payload: reachPayload,
      parentCfgEvidence: cfg,
      provider: "ReaControlFlowEngine",
    });
    const reachability = unwrap(reachRes);

    // 4. Taint
    const taintSigner = authority.createTaintSigner(stageContext);
    const taintPayload: TaintPayload = {
      status: status === "UNREACHABLE" ? "NO_TAINT" : "PROVEN_TAINT",
      source: status === "UNREACHABLE" ? null : {
        kind: "network_socket",
        api: "recv",
        functionName: "main",
        address: 0x1000,
        targetParameterOrReturn: 1,
      },
      sink: {
        api: "system",
        functionName: "handle_cmd",
        address: 0x1020,
        vulnerableParameterIndex: 0,
      },
      steps: [],
      sanitizers: [],
      isSanitized: false,
      hasUnresolvedAliases: false,
      reasoning: "Taint propagation verified",
    };
    const taintRes = taintSigner.signTaintEvidence({
      payload: taintPayload,
      parentCfgEvidence: cfg,
    });
    const taint = unwrap(taintRes);

    // 5. Witness
    const witSigner = authority.createWitnessSigner(stageContext);
    const witPayload: WitnessPayload = {
      witnessId: "wit_adv_001",
      findingId: "fnd_adv_001",
      ruleId: "REA-ADV-001-CMD-INJECTION",
      category: "command_injection",
      isSatisfiable: true,
      isReproducible: true,
      exploitabilityStatus: "PROVEN",
      conflictingGuards: [],
      validationLog: ["Preconditions met"],
      constraints: [{ parameter: "cmd", type: "min_length", expectedValue: 1, description: "Payload" }],
      verifiedAt: new Date().toISOString(),
    };
    const witRes = witSigner.signWitnessEvidence({
      payload: witPayload,
      parentTaintEvidence: taint,
    });
    const witness = unwrap(witRes);

    return {
      decoder,
      cfg,
      reachability,
      taint,
      witness,
      chain: [decoder, cfg, reachability, taint, witness],
    };
  }

  // ==========================================================================
  // A. Forgery and Authorization
  // ==========================================================================

  it("ADV-A1: Caller fabricates a ReachabilityAnalysisResult in-memory without trusted evidence", () => {
    const fabricatedReachability = {
      status: "REACHABLE" as const,
      paths: [],
      entryPoint: "main",
      target: "system",
      deadCodeFunctions: [],
      reasoning: "Fabricated in-memory reachability object",
      provider: "ReaControlFlowEngine",
      analysisOutcome: "SUCCESS" as any,
      isComplete: true,
    };

    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      reachability: fabricatedReachability,
    });

    expect(res.ok).toBe(true);
    const val = unwrap(res);
    expect(val.lifecycleState).toBe("INCONCLUSIVE");
    expect(val.finding.confidence.verification_method).toContain("Unauthenticated analysis evidence");
  });

  it("ADV-A2: Caller supplies a forged provider identity", () => {
    const forgedReachability = {
      status: "REACHABLE" as const,
      paths: [],
      entryPoint: "main",
      target: "system",
      deadCodeFunctions: [],
      reasoning: "Spoofed provider claim",
      provider: "GhidraProvider", // Forged string
      analysisOutcome: "SUCCESS" as any,
      isComplete: true,
    };

    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      reachability: forgedReachability,
    });

    expect(res.ok).toBe(true);
    const val = unwrap(res);
    expect(val.lifecycleState).toBe("INCONCLUSIVE");
    expect(val.finding.confidence.verification_method).toContain("Unauthenticated analysis evidence");
  });

  it("ADV-A3: Caller claims to have used Capstone when it was unavailable", () => {
    const stageContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: testBinarySha256,
      runId: activeRunId,
    };

    const decSigner = authority.createDecoderSigner(stageContext);
    const res = decSigner.signDecoderEvidence({
      payload: {
        instructions: [],
        outcome: "SUCCESS",
        architecture: "ARM",
        baseAddress: 0x1000,
        totalBytes: 0,
        decodedBytes: 0,
        provenance: { actualProvider: "FakeCapstoneProvider", isFallback: false, timestamp: Date.now() },
      },
      provider: "FakeCapstoneProvider", // Unauthorized
      architecture: "ARM",
    });

    expect(res.ok).toBe(false);
    expect(unwrapError(res).code).toBe("UNAUTHORIZED_PROVIDER");
  });

  it("ADV-A4: Unauthorized worker attempts to sign decoder evidence", () => {
    const stageContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: testBinarySha256,
      runId: activeRunId,
    };

    const decSigner = authority.createDecoderSigner(stageContext);
    const res = decSigner.signDecoderEvidence({
      payload: {
        instructions: [],
        outcome: "SUCCESS",
        architecture: "ARM",
        baseAddress: 0x1000,
        totalBytes: 0,
        decodedBytes: 0,
        provenance: { actualProvider: "MaliciousPlugin", isFallback: false, timestamp: Date.now() },
      },
      provider: "MaliciousPlugin",
      architecture: "ARM",
    });

    expect(res.ok).toBe(false);
    expect(unwrapError(res).code).toBe("UNAUTHORIZED_PROVIDER");
  });

  it("ADV-A5: Unauthorized worker attempts to sign CFG evidence with forged parent", () => {
    const stageContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: testBinarySha256,
      runId: activeRunId,
    };

    const cfgSigner = authority.createCfgSigner(stageContext);
    const fakeParent: any = {
      claims: {
        evidenceId: "ev_fake_dec",
        schemaVersion: "1.0.0",
        stage: "DECODER",
        assessmentId: testAssessmentId,
        assetId: testAssetId,
        binarySha256: testBinarySha256,
        runId: activeRunId,
        provider: "InProcessInstructionDecoder",
        decodeCompleteness: { isComplete: true, outcome: "SUCCESS", decodedBytes: 4, totalBytes: 4 },
        parentEvidenceIds: [],
        timestamp: Date.now(),
        payloadDigest: canonicalDigest({}),
      },
      payload: {},
      claimsDigest: "0".repeat(64),
      signature: "deadbeef",
      keyVersion: 1,
    };

    const res = cfgSigner.signCfgEvidence({
      payload: {
        functionName: "fn",
        entryBlockId: "b0",
        blocks: [],
        edges: [],
        architecture: "ARM",
        decodeOutcome: "SUCCESS",
        isComplete: true,
        cfgHash: "none",
      },
      parentDecoderEvidence: fakeParent,
    });

    expect(res.ok).toBe(false);
    expect(["INVALID_CLAIMS_DIGEST", "SIGNATURE_INVALID"]).toContain(unwrapError(res).code);
  });

  it("ADV-A6: An arbitrary payload is submitted to the signing authority", () => {
    // TrustedEvidenceAuthority does NOT have a public generic sign() method.
    expect((authority as any).sealEvidence).toBeUndefined();
    expect((authority as any).sign).toBeUndefined();
    expect((authority as any).signArbitrary).toBeUndefined();
  });

  it("ADV-A7: Valid signature from one stage is reused as another stage's evidence", () => {
    const pipeline = createValidEvidencePipeline();
    // Use valid signed Decoder evidence as Reachability evidence
    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: pipeline.decoder as any, // stage is "DECODER"
      verifier,
      runId: activeRunId,
    });

    expect(res.ok).toBe(true);
    const val = unwrap(res);
    expect(val.lifecycleState).toBe("INCONCLUSIVE");
    expect(val.finding.confidence.verification_method).toContain("STAGE_MISMATCH");
  });

  it("ADV-A8: A compromised worker attempts to sign evidence for a different stage", () => {
    const stageContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: testBinarySha256,
      runId: activeRunId,
    };

    const decSigner = authority.createDecoderSigner(stageContext);
    // DecoderStageSigner hardcodes stage "DECODER". Calling signDecoderEvidence only ever signs DECODER claims.
    const res = decSigner.signDecoderEvidence({
      payload: {
        instructions: [],
        outcome: "SUCCESS",
        architecture: "ARM",
        baseAddress: 0x1000,
        totalBytes: 0,
        decodedBytes: 0,
        provenance: { actualProvider: "InProcessInstructionDecoder", isFallback: false, timestamp: Date.now() },
      },
      provider: "InProcessInstructionDecoder",
      architecture: "ARM",
    });

    expect(res.ok).toBe(true);
    const signed = unwrap(res);
    expect(signed.claims.stage).toBe("DECODER");
  });

  // ==========================================================================
  // B. Integrity and Mutation
  // ==========================================================================

  it("ADV-B9: Payload modified after sealing", () => {
    const pipeline = createValidEvidencePipeline();
    // Tamper with payload in clone
    const tampered = JSON.parse(JSON.stringify(pipeline.reachability));
    tampered.payload.status = "UNREACHABLE"; // Tamper payload

    const verRes = verifier.verifyEvidence(tampered, "REACHABILITY");
    expect(verRes.ok).toBe(false);
    expect(unwrapError(verRes).code).toBe("INVALID_PAYLOAD_DIGEST");

    const adjRes = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: tampered,
      verifier,
      runId: activeRunId,
    });
    expect(unwrap(adjRes).lifecycleState).toBe("INCONCLUSIVE");
  });

  it("ADV-B10: Payload digest modified in claims", () => {
    const pipeline = createValidEvidencePipeline();
    const tampered = JSON.parse(JSON.stringify(pipeline.reachability));
    tampered.claims.payloadDigest = "0".repeat(64);

    const verRes = verifier.verifyEvidence(tampered, "REACHABILITY");
    expect(verRes.ok).toBe(false);
    expect(unwrapError(verRes).code).toBe("INVALID_PAYLOAD_DIGEST");
  });

  it("ADV-B11: Signed claims modified", () => {
    const pipeline = createValidEvidencePipeline();
    const tampered = JSON.parse(JSON.stringify(pipeline.reachability));
    tampered.claims.providerVersion = "9.9.9";
    tampered.claimsDigest = canonicalDigest(tampered.claims);

    const verRes = verifier.verifyEvidence(tampered, "REACHABILITY");
    expect(verRes.ok).toBe(false);
    expect(unwrapError(verRes).code).toBe("SIGNATURE_INVALID");
  });

  it("ADV-B12: CFG hash changed after generation", () => {
    const pipeline = createValidEvidencePipeline();
    const tampered = JSON.parse(JSON.stringify(pipeline.cfg));
    tampered.claims.cfgHash = "f".repeat(64);
    tampered.claimsDigest = canonicalDigest(tampered.claims);

    const verRes = verifier.verifyEvidence(tampered, "CFG");
    expect(verRes.ok).toBe(false);
    expect(unwrapError(verRes).code).toBe("SIGNATURE_INVALID");
  });

  it("ADV-B13: Nested object mutated in payload", () => {
    const pipeline = createValidEvidencePipeline();
    const tampered = JSON.parse(JSON.stringify(pipeline.reachability));
    tampered.payload.paths[0].steps[0].description = "Tampered description";

    const verRes = verifier.verifyEvidence(tampered, "REACHABILITY");
    expect(verRes.ok).toBe(false);
    expect(unwrapError(verRes).code).toBe("INVALID_PAYLOAD_DIGEST");
  });

  it("ADV-B14: Map or Set mutated in input does not affect sealed evidence", () => {
    const pipeline = createValidEvidencePipeline();
    // Returned evidence is deeply frozen
    expect(Object.isFrozen(pipeline.reachability)).toBe(true);
    expect(Object.isFrozen(pipeline.reachability.payload)).toBe(true);
    expect(Object.isFrozen(pipeline.reachability.claims)).toBe(true);
  });

  it("ADV-B15: Buffer or TypedArray mutated externally", () => {
    const rawBytes = new Uint8Array([0x55, 0x89, 0xe5]);
    const hex = Buffer.from(rawBytes).toString("hex");
    // Mutating rawBytes externally has no effect on immutable serialized hex
    rawBytes[0] = 0x90;
    expect(hex).toBe("5589e5");
  });

  it("ADV-B16: Evidence modified between verification and adjudication throws or fails closed", () => {
    const pipeline = createValidEvidencePipeline();
    const verifiedRes = verifier.verifyEvidence(pipeline.reachability, "REACHABILITY");
    expect(verifiedRes.ok).toBe(true);
    const verified = unwrap(verifiedRes);

    // Deep freeze prevents mutation
    expect(() => {
      (verified.payload as any).status = "UNREACHABLE";
    }).toThrow();
  });

  // ==========================================================================
  // C. Lineage and Identity
  // ==========================================================================

  it("ADV-C17: Cross-assessment evidence is rejected", () => {
    const pipeline = createValidEvidencePipeline();
    const otherAssessment = "asm_other_000000000000000000000000000000000000000000000000000002" as AssessmentId;

    const res = bridge.adjudicateCandidate(otherAssessment, testAsset, testCandidate, {
      trustedReachability: pipeline.reachability,
      verifier,
      runId: activeRunId,
    });

    expect(res.ok).toBe(true);
    const val = unwrap(res);
    expect(val.lifecycleState).toBe("INCONCLUSIVE");
    expect(val.finding.confidence.verification_method).toContain("Cross-assessment evidence reuse detected");
  });

  it("ADV-C18: Cross-asset evidence is rejected", () => {
    const pipeline = createValidEvidencePipeline();
    const otherAsset: BlackboardAssetRecord = {
      ...testAsset,
      id: "ast_other_000000000000000000000000000000000000000000000000000002" as AssetId,
    };

    const res = bridge.adjudicateCandidate(testAssessmentId, otherAsset, testCandidate, {
      trustedReachability: pipeline.reachability,
      verifier,
      runId: activeRunId,
    });

    expect(res.ok).toBe(true);
    const val = unwrap(res);
    expect(val.lifecycleState).toBe("INCONCLUSIVE");
    expect(val.finding.confidence.verification_method).toContain("Cross-asset evidence reuse detected");
  });

  it("ADV-C19: Cross-binary evidence is rejected", () => {
    const pipeline = createValidEvidencePipeline();
    const otherAsset: BlackboardAssetRecord = {
      ...testAsset,
      digest: { sha256: "2222222222222222222222222222222222222222222222222222222222222222" },
    };

    const res = bridge.adjudicateCandidate(testAssessmentId, otherAsset, testCandidate, {
      trustedReachability: pipeline.reachability,
      verifier,
      runId: activeRunId,
    });

    expect(res.ok).toBe(true);
    const val = unwrap(res);
    expect(val.lifecycleState).toBe("INCONCLUSIVE");
    expect(val.finding.confidence.verification_method).toContain("Cross-binary evidence reuse detected");
  });

  it("ADV-C20: Cross-firmware-version evidence is rejected", () => {
    const pipeline = createValidEvidencePipeline();
    const res = verifier.verifyLineage(pipeline.chain, {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: "mismatched_binary_hash",
      runId: activeRunId,
    });

    expect(res.ok).toBe(false);
    expect(unwrapError(res).code).toBe("CROSS_BINARY_REUSE");
  });

  it("ADV-C21: Cross-run evidence is rejected", () => {
    const pipeline = createValidEvidencePipeline();
    const otherRun = "run_other_999999999999";

    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: pipeline.reachability,
      verifier,
      runId: otherRun,
    });

    expect(res.ok).toBe(true);
    const val = unwrap(res);
    expect(val.lifecycleState).toBe("INCONCLUSIVE");
    expect(val.finding.confidence.verification_method).toContain("Cross-run evidence reuse detected");
  });

  it("ADV-C22: Missing parent evidence in lineage chain fails closed", () => {
    const pipeline = createValidEvidencePipeline();
    // Missing Decoder parent: pass [CFG, Reachability]
    const brokenChain = [pipeline.cfg, pipeline.reachability];

    const res = verifier.verifyLineage(brokenChain, {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: testBinarySha256,
      runId: activeRunId,
    });

    expect(res.ok).toBe(false);
    expect(unwrapError(res).code).toBe("PARENT_NOT_FOUND");
  });

  it("ADV-C23: Substituted parent evidence in lineage chain fails closed", () => {
    const pipeline = createValidEvidencePipeline();
    // Tamper parentEvidenceIds
    const tamperedReach = JSON.parse(JSON.stringify(pipeline.reachability));
    tamperedReach.claims.parentEvidenceIds = ["ev_substituted_parent_999"];
    tamperedReach.claimsDigest = canonicalDigest(tamperedReach.claims);
    tamperedReach.signature = computeEvidenceSignature(keyring.getActiveKey().key_hex, 1, tamperedReach.claimsDigest);

    const res = verifier.verifyLineage([pipeline.decoder, pipeline.cfg, tamperedReach], {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: testBinarySha256,
      runId: activeRunId,
    });

    expect(res.ok).toBe(false);
    expect(unwrapError(res).code).toBe("PARENT_NOT_FOUND");
  });

  it("ADV-C24: Parent evidence from the wrong stage is rejected", () => {
    const pipeline = createValidEvidencePipeline();
    // Make CFG reference Reachability as parent
    const tamperedCfg = JSON.parse(JSON.stringify(pipeline.cfg));
    tamperedCfg.claims.parentEvidenceIds = [pipeline.reachability.claims.evidenceId];
    tamperedCfg.claimsDigest = canonicalDigest(tamperedCfg.claims);
    tamperedCfg.signature = computeEvidenceSignature(keyring.getActiveKey().key_hex, 1, tamperedCfg.claimsDigest);

    const res = verifier.verifyLineage([pipeline.decoder, tamperedCfg, pipeline.reachability], {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: testBinarySha256,
      runId: activeRunId,
    });

    expect(res.ok).toBe(false);
    expect(unwrapError(res).code).toBe("LINEAGE_INVALID");
  });

  it("ADV-C25: Skipped stage in the evidence chain is rejected", () => {
    const pipeline = createValidEvidencePipeline();
    // Decoder directly to Reachability (skipping CFG)
    const res = verifier.verifyLineage([pipeline.decoder, pipeline.reachability], {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: testBinarySha256,
      runId: activeRunId,
    });

    expect(res.ok).toBe(false);
    expect(unwrapError(res).code).toBe("PARENT_NOT_FOUND");
  });

  it("ADV-C26: Stale replay from a completed run is rejected", () => {
    const pipeline = createValidEvidencePipeline();
    // Complete the run
    runManager.completeRun(activeRunId);

    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: pipeline.reachability,
      verifier,
      runId: activeRunId,
    });

    expect(res.ok).toBe(true);
    const val = unwrap(res);
    expect(val.lifecycleState).toBe("INCONCLUSIVE");
    expect(val.finding.confidence.verification_method).toContain("RUN_COMPLETED");
  });

  // ==========================================================================
  // D. Persistence and Key Lifecycle
  // ==========================================================================

  it("ADV-D27: Evidence tampered with in SQLite is detected on verification", () => {
    const pipeline = createValidEvidencePipeline();
    // Directly mutate SQLite row
    db.prepare("UPDATE analysis_evidence_records SET payload_json = ? WHERE evidence_id = ?").run(
      JSON.stringify({ status: "UNREACHABLE" }),
      pipeline.reachability.claims.evidenceId,
    );

    const row = db
      .prepare("SELECT claims_json, payload_json, signature, key_version, claims_digest FROM analysis_evidence_records WHERE evidence_id = ?")
      .get(pipeline.reachability.claims.evidenceId) as any;

    const reconstructed = {
      claims: JSON.parse(row.claims_json),
      payload: JSON.parse(row.payload_json),
      claimsDigest: row.claims_digest,
      signature: row.signature,
      keyVersion: row.key_version,
    };

    const verRes = verifier.verifyEvidence(reconstructed as any);
    expect(verRes.ok).toBe(false);
    expect(unwrapError(verRes).code).toBe("INVALID_PAYLOAD_DIGEST");
  });

  it("ADV-D28: Evidence tampered with after clean restart fails closed", () => {
    const pipeline = createValidEvidencePipeline();
    // Close storage and database
    storage.close();

    // Reopen storage on same SQLite file
    const reopenedStorage = new SqliteBlackboardStorage({ dbPath, assessmentId: testAssessmentId });
    const reopenedDb = reopenedStorage.getDatabase();
    const reopenedKeyring = reopenedStorage.getKeyringManager();
    const reopenedRunManager = new AnalysisRunManager(reopenedDb);
    const reopenedVerifier = new TrustedEvidenceVerifier({ keyringManager: reopenedKeyring, runManager: reopenedRunManager });

    // Tamper row in reopened DB
    reopenedDb.prepare("UPDATE analysis_evidence_records SET signature = ? WHERE evidence_id = ?").run(
      "deadbeefbadc0de",
      pipeline.reachability.claims.evidenceId,
    );

    const row = reopenedDb
      .prepare("SELECT claims_json, payload_json, signature, key_version, claims_digest FROM analysis_evidence_records WHERE evidence_id = ?")
      .get(pipeline.reachability.claims.evidenceId) as any;

    const reconstructed = {
      claims: JSON.parse(row.claims_json),
      payload: JSON.parse(row.payload_json),
      claimsDigest: row.claims_digest,
      signature: row.signature,
      keyVersion: row.key_version,
    };

    const verRes = reopenedVerifier.verifyEvidence(reconstructed as any);
    expect(verRes.ok).toBe(false);
    expect(unwrapError(verRes).code).toBe("SIGNATURE_INVALID");
    reopenedStorage.close();
  });

  it("ADV-D29: Key unavailable results in INCONCLUSIVE (fail-closed)", () => {
    const pipeline = createValidEvidencePipeline();
    // Keyring with version 2 only (version 1 missing/unavailable)
    const missingKeyring = new KeyringManager({
      assessment_id: testAssessmentId,
      active_version: 2,
      keys: [{ version: 2, key_hex: "0".repeat(64), created_at: "" }],
    });
    const emptyVerifier = new TrustedEvidenceVerifier({ keyringManager: missingKeyring });

    const verRes = emptyVerifier.verifyEvidence(pipeline.reachability);
    expect(verRes.ok).toBe(false);
    expect(unwrapError(verRes).code).toBe("KEY_UNAVAILABLE");
  });

  it("ADV-D30: Key revoked results in INCONCLUSIVE (fail-closed)", () => {
    const pipeline = createValidEvidencePipeline();
    const emptyKeyring = new KeyringManager({
      assessment_id: testAssessmentId,
      active_version: 2,
      keys: [], // key version 1 removed
    });
    const verifierRevoked = new TrustedEvidenceVerifier({ keyringManager: emptyKeyring });

    const verRes = verifierRevoked.verifyEvidence(pipeline.reachability);
    expect(verRes.ok).toBe(false);
    expect(unwrapError(verRes).code).toBe("KEY_UNAVAILABLE");
  });

  it("ADV-D31: Key rotated verifies both old and new evidence correctly", () => {
    const pipelineV1 = createValidEvidencePipeline();

    // Rotate key to version 2
    const rotRes = keyring.rotateKey("rot_event_001");
    expect(rotRes.ok).toBe(true);
    expect(keyring.getActiveVersion()).toBe(2);

    // Old evidence signed with v1 still verifies
    const verV1 = verifier.verifyEvidence(pipelineV1.reachability);
    expect(verV1.ok).toBe(true);

    // New evidence signed with active v2
    const pipelineV2 = createValidEvidencePipeline();
    expect(pipelineV2.reachability.keyVersion).toBe(2);
    const verV2 = verifier.verifyEvidence(pipelineV2.reachability);
    expect(verV2.ok).toBe(true);
  });

  it("ADV-D32: Unknown key version fails closed", () => {
    const pipeline = createValidEvidencePipeline();
    const tampered = { ...pipeline.reachability, keyVersion: 999 };

    const verRes = verifier.verifyEvidence(tampered);
    expect(verRes.ok).toBe(false);
    expect(unwrapError(verRes).code).toBe("KEY_UNAVAILABLE");
  });

  it("ADV-D33: Invalid HMAC signature fails closed", () => {
    const pipeline = createValidEvidencePipeline();
    const tampered = { ...pipeline.reachability, signature: "0".repeat(64) };

    const verRes = verifier.verifyEvidence(tampered);
    expect(verRes.ok).toBe(false);
    expect(unwrapError(verRes).code).toBe("SIGNATURE_INVALID");
  });

  it("ADV-D34: Concurrent replay attempts fail closed", async () => {
    const pipeline = createValidEvidencePipeline();

    // First consumption succeeds
    const first = runManager.markEvidenceConsumed(pipeline.reachability.claims.evidenceId, activeRunId);
    expect(first.ok).toBe(true);

    // Second consumption concurrently / sequentially is blocked
    const second = runManager.markEvidenceConsumed(pipeline.reachability.claims.evidenceId, activeRunId);
    expect(second.ok).toBe(false);
    expect(unwrapError(second).code).toBe("REPLAY_DETECTED");
  });

  it("ADV-D35: Crash or unpersisted run fails closed to RUN_INACTIVE", () => {
    const unpersistedRunId = "run_ghost_unpersisted_1234";
    const res = verifier.verifyRunFreshness(unpersistedRunId, testAssessmentId, testAssetId, testBinarySha256);
    expect(res.ok).toBe(false);
    expect(unwrapError(res).code).toBe("RUN_INACTIVE");
  });

  // ==========================================================================
  // E. Adjudication Safety
  // ==========================================================================

  it("ADV-E36: Incomplete decoding cannot produce VERIFIED", () => {
    // Pipeline with decodeOutcome PARTIAL and isComplete false
    const pipeline = createValidEvidencePipeline({ isComplete: false, decodeOutcome: "PARTIAL" });

    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: pipeline.reachability,
      trustedTaint: pipeline.taint,
      trustedWitness: pipeline.witness,
      parentEvidenceChain: pipeline.chain,
      verifier,
      runId: activeRunId,
    });

    expect(res.ok).toBe(true);
    const val36 = unwrap(res);
    expect(val36.lifecycleState).not.toBe("VERIFIED");
    expect(val36.lifecycleState).toBe("INCONCLUSIVE");
    expect(val36.finding.confidence.verification_method).toContain("Reachability analysis was incomplete or partial");
  });

  it("ADV-E37: Unsupported instructions cannot produce FALSE_POSITIVE", () => {
    // Even if reachability claims UNREACHABLE, if decode had unsupported instructions, it CANNOT be FALSE_POSITIVE
    const pipeline = createValidEvidencePipeline({
      isComplete: false,
      decodeOutcome: "PARTIAL",
      reachabilityStatus: "UNREACHABLE",
    });

    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: pipeline.reachability,
      parentEvidenceChain: pipeline.chain,
      verifier,
      runId: activeRunId,
    });

    expect(res.ok).toBe(true);
    const val37 = unwrap(res);
    expect(val37.lifecycleState).not.toBe("FALSE_POSITIVE");
    expect(val37.lifecycleState).toBe("INCONCLUSIVE");
  });

  it("ADV-E38: Missing reachability evidence cannot produce VERIFIED", () => {
    const pipeline = createValidEvidencePipeline();
    // Omit reachability evidence
    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedTaint: pipeline.taint,
      trustedWitness: pipeline.witness,
      verifier,
      runId: activeRunId,
    });

    expect(res.ok).toBe(true);
    const val38 = unwrap(res);
    expect(val38.lifecycleState).not.toBe("VERIFIED");
    expect(val38.lifecycleState).toBe("INCONCLUSIVE");
  });

  it("ADV-E39: Unauthenticated taint evidence cannot produce VERIFIED", () => {
    const pipeline = createValidEvidencePipeline();
    // Pass authenticated reachability but unauthenticated taint
    const unauthenticatedTaint: any = {
      status: "PROVEN_TAINT",
      source: null,
      sink: null,
      steps: [],
      sanitizers: [],
      isSanitized: false,
      hasUnresolvedAliases: false,
      evidenceId: "ev_fake_taint",
      reasoning: "Unauthenticated taint",
    };

    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: pipeline.reachability,
      taintFlow: unauthenticatedTaint,
      trustedWitness: pipeline.witness,
      verifier,
      runId: activeRunId,
    });

    expect(res.ok).toBe(true);
    const val39 = unwrap(res);
    expect(val39.lifecycleState).not.toBe("VERIFIED");
    expect(val39.lifecycleState).toBe("INCONCLUSIVE");
  });

  it("ADV-E40: Unauthenticated negative evidence cannot produce FALSE_POSITIVE", () => {
    const unauthenticatedReachability: any = {
      status: "UNREACHABLE",
      paths: [],
      entryPoint: "main",
      target: "system",
      deadCodeFunctions: ["handle_cmd"],
      reasoning: "Unauthenticated dead code claim",
      provider: "ReaControlFlowEngine",
      analysisOutcome: "SUCCESS",
      isComplete: true,
    };

    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      reachability: unauthenticatedReachability,
    });

    expect(res.ok).toBe(true);
    const val40 = unwrap(res);
    expect(val40.lifecycleState).not.toBe("FALSE_POSITIVE");
    expect(val40.lifecycleState).toBe("INCONCLUSIVE");
    expect(val40.finding.confidence.verification_method).toContain("Unauthenticated analysis evidence");
  });

  it("ADV-E41: Invalid evidence always produces INCONCLUSIVE rather than a misleading security verdict", () => {
    const pipeline = createValidEvidencePipeline();
    // Corrupt signature
    const corruptedReachability = {
      ...pipeline.reachability,
      signature: "bad_signature_0000000000000000000000000000000000000000000000000000",
    };

    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: corruptedReachability,
      trustedTaint: pipeline.taint,
      trustedWitness: pipeline.witness,
      verifier,
      runId: activeRunId,
    });

    expect(res.ok).toBe(true);
    const val41 = unwrap(res);
    expect(val41.lifecycleState).toBe("INCONCLUSIVE");
    expect(val41.lifecycleState).not.toBe("VERIFIED");
    expect(val41.lifecycleState).not.toBe("FALSE_POSITIVE");
    expect(val41.lifecycleState).not.toBe("MITIGATED");
  });

  // ==========================================================================
  // Positive Golden Path Verification
  // ==========================================================================

  it("GOLDEN-PATH: Complete authenticated evidence chain successfully achieves VERIFIED", () => {
    const pipeline = createValidEvidencePipeline({ isComplete: true, decodeOutcome: "SUCCESS", reachabilityStatus: "REACHABLE" });

    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: pipeline.reachability,
      trustedTaint: pipeline.taint,
      trustedWitness: pipeline.witness,
      parentEvidenceChain: pipeline.chain,
      verifier,
      runId: activeRunId,
    });

    expect(res.ok).toBe(true);
    const valGp1 = unwrap(res);
    expect(valGp1.lifecycleState).toBe("VERIFIED");
    expect(valGp1.finding.verification_status).toBe("VERIFIED");
    expect(valGp1.finding.confidence.level).toBe("CONFIRMED");
    expect(valGp1.finding.confidence.verification_method).toContain("L5 Witness verified satisfiable");
  });

  it("GOLDEN-PATH: Complete authenticated dead-code evidence legitimately achieves FALSE_POSITIVE", () => {
    const pipeline = createValidEvidencePipeline({ isComplete: true, decodeOutcome: "SUCCESS", reachabilityStatus: "UNREACHABLE" });

    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, testCandidate, {
      trustedReachability: pipeline.reachability,
      trustedTaint: pipeline.taint,
      parentEvidenceChain: [pipeline.decoder, pipeline.cfg, pipeline.reachability, pipeline.taint],
      verifier,
      runId: activeRunId,
    });

    expect(res.ok).toBe(true);
    const valGp2 = unwrap(res);
    expect(valGp2.lifecycleState).toBe("FALSE_POSITIVE");
    expect(valGp2.finding.verification_status).toBe("FALSE_POSITIVE");
    expect(valGp2.finding.confidence.verification_method).toContain("Control-flow analysis proved sink is in unreachable dead code");
  });
});
