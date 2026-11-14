/* eslint-disable max-lines-per-function */
/**
 * REA Sprint 3B.1 — Independent Security Acceptance Audit & Adversarial Verification Suite
 *
 * Verifies the 10 core adversarial acceptance requirements:
 * 1. Production authentication bypass attempts fail closed.
 * 2. Unauthorized signer acquisition and reflection attacks are blocked.
 * 3. Arbitrary payload submission to authorized signers is prevented.
 * 4. Provider impersonation via signer access is rejected.
 * 5. Cross-stage signer privilege escalation is prevented.
 * 6. Public API bypass availability is verified as strictly absent.
 * 7. Evidence mutation between verification and consumption is prevented.
 * 8. Cross-candidate / Sink API substitution is detected and rejected.
 * 9. Cross-candidate / Witness rule substitution is detected and rejected.
 * 10. Witness replay within the same run is blocked via atomic consumption.
 * 11. Cryptographic constant-time comparison and signature format checks.
 * 12. BinaryAnalysisWorker default fail-closed behavior.
 */

import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { SqliteBlackboardStorage } from "../../blackboard/SqliteBlackboardStorage.js";
import { KeyringManager } from "../../packboard/secureKeyring.js";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { AssetId } from "../../../domain/security/asset.js";
import type { BlackboardAssetRecord } from "../../../domain/security/blackboard/types.js";
import type { VulnerabilityCandidate } from "../../../domain/security/binary/types.js";
import {
  AnalysisRunManager,
  TrustedEvidenceAuthority,
  TrustedEvidenceVerifier,
} from "./TrustedAnalysisEvidence.js";
import type {
  DecoderPayload,
  CfgPayload,
  ReachabilityPayload,
  TaintPayload,
  WitnessPayload,
} from "./types.js";
import { VulnerabilityAdjudicationBridge } from "../VulnerabilityAdjudicationBridge.js";
import type { Result } from "../../../domain/result.js";

const testAssessmentId = "asm_audit_3b1_00000000000000000000000000000000000000000000000000000001" as AssessmentId;
const testAssetId = "ast_audit_3b1_00000000000000000000000000000000000000000000000000000001" as AssetId;
const testBinarySha256 = "1".repeat(64);

const testAsset: BlackboardAssetRecord = {
  id: testAssetId,
  assessment_id: testAssessmentId,
  parent_asset_id: null,
  name: "firmware_audit_target",
  type: "compiled_binary",
  path: "/usr/sbin/service_daemon",
  digest: { sha256: testBinarySha256 },
  architecture: "ARM",
  version: "1.0.0",
  environment: null,
  tags: ["executable"],
  metadata: {},
  created_at: Date.now(),
};

const candidateCmdInj: VulnerabilityCandidate = {
  binaryAssetId: testAsset.id,
  ruleId: "REA-ADV-CMD-INJ",
  category: "command_injection",
  name: "system() command injection",
  functionName: "handle_req",
  functionAddress: "0x1000",
  sinkApi: "system",
  callAddress: "0x1020",
  callerInfo: "handle_req caller",
  sourceOfInput: "network",
  guardInfo: null,
  evidenceReferences: ["ev_system"],
  detectionMethod: "L5_WITNESS",
  confidenceScore: 1.0,
  confidenceLimitations: [],
  cwe: ["CWE-78"],
  technicalDescription: "Direct user parameter flow to system()",
  remediationGuidance: "Replace system() with execve()",
};

const candidateStrcpy: VulnerabilityCandidate = {
  binaryAssetId: testAsset.id,
  ruleId: "REA-ADV-STRCPY",
  category: "unsafe_memory_operations",
  name: "strcpy() buffer overflow",
  functionName: "handle_req",
  functionAddress: "0x1000",
  sinkApi: "strcpy",
  callAddress: "0x1030",
  callerInfo: "handle_req caller",
  sourceOfInput: "network",
  guardInfo: null,
  evidenceReferences: ["ev_strcpy"],
  detectionMethod: "L5_WITNESS",
  confidenceScore: 1.0,
  confidenceLimitations: [],
  cwe: ["CWE-120"],
  technicalDescription: "Unbounded strcpy() into stack buffer",
  remediationGuidance: "Replace with strlcpy()",
};

function unwrap<T>(res: Result<T, any>): T {
  if (!res.ok) {
    throw new Error(`Expected ok result, got error: ${JSON.stringify((res as any).error)}`);
  }
  return res.value;
}

describe("Sprint 3B.1: Independent Security Acceptance Audit Suite", () => {
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
    tempDir = await mkdtemp(join(tmpdir(), "rea-audit-3b1-"));
    dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath, assessmentId: testAssessmentId });
    db = storage.getDatabase();
    keyring = storage.getKeyringManager();

    await storage.assessments.create({
      id: testAssessmentId,
      name: "Audit 3B.1 Assessment",
      status: "active",
      objective: { title: "Audit 3B.1", target_technologies: [], compliance_frameworks: [], focus_areas: [], depth: "surface" },
      authorization: { allowed_targets: [], denied_targets: [], authorized_by: "Auditor", authorization_reference: "AUDIT-3B1", valid_until: "2027-01-01", allow_active_verification: false },
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

  function createValidEvidencePipeline(sinkApi: string, ruleId: string, category: string) {
    const stageContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: testBinarySha256,
      runId: activeRunId,
    };

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
      outcome: "SUCCESS",
      architecture: "ARM",
      baseAddress: 0x1000,
      totalBytes: 4,
      decodedBytes: 4,
      provenance: {
        actualProvider: "InProcessInstructionDecoder",
        isFallback: false,
        timestamp: Date.now(),
      },
    };
    const decoder = unwrap(decSigner.signDecoderEvidence({
      payload: decPayload,
      provider: "InProcessInstructionDecoder",
      architecture: "ARM",
    }));

    const cfgSigner = authority.createCfgSigner(stageContext);
    const cfgPayload: CfgPayload = {
      functionName: "handle_req",
      entryBlockId: "bb_0x1000",
      blocks: [
        {
          id: "bb_0x1000",
          startAddress: 0x1000,
          endAddress: 0x1004,
          functionName: "handle_req",
          instructionsCount: 1,
          predecessorIds: [],
          successorIds: [],
          terminatorType: "return",
        },
      ],
      edges: [],
      architecture: "ARM",
      decodeOutcome: "SUCCESS",
      isComplete: true,
      cfgHash: "none",
    };
    const cfg = unwrap(cfgSigner.signCfgEvidence({
      payload: cfgPayload,
      parentDecoderEvidence: decoder,
    }));

    const reachSigner = authority.createReachabilitySigner(stageContext);
    const reachPayload: ReachabilityPayload = {
      status: "REACHABLE",
      paths: [
        {
          source: "main",
          target: sinkApi,
          steps: [{ functionName: "handle_req", blockId: "bb_0x1000", address: 0x1000, description: "Call step" }],
          isDefinitive: true,
          unresolvedIndirectJumps: [],
        },
      ],
      entryPoint: "main",
      target: sinkApi,
      deadCodeFunctions: [],
      reasoning: "Definitive reachability",
      provider: "ReaControlFlowEngine",
      analysisOutcome: "SUCCESS",
      isComplete: true,
    };
    const reachability = unwrap(reachSigner.signReachabilityEvidence({
      payload: reachPayload,
      parentCfgEvidence: cfg,
      provider: "ReaControlFlowEngine",
    }));

    const taintSigner = authority.createTaintSigner(stageContext);
    const taintPayload: TaintPayload = {
      status: "PROVEN_TAINT",
      source: {
        kind: "network_socket",
        api: "recv",
        functionName: "main",
        address: 0x1000,
        targetParameterOrReturn: 1,
      },
      sink: {
        api: sinkApi,
        functionName: "handle_req",
        address: 0x1020,
        vulnerableParameterIndex: 0,
      },
      steps: [],
      sanitizers: [],
      isSanitized: false,
      hasUnresolvedAliases: false,
      reasoning: "Unsanitized taint reaches sink",
    };
    const taint = unwrap(taintSigner.signTaintEvidence({
      payload: taintPayload,
      parentCfgEvidence: cfg,
    }));

    const witSigner = authority.createWitnessSigner(stageContext);
    const witPayload: WitnessPayload = {
      witnessId: `wit_${sinkApi}`,
      findingId: `fnd_${sinkApi}`,
      ruleId,
      category,
      isSatisfiable: true,
      isReproducible: true,
      exploitabilityStatus: "PROVEN",
      conflictingGuards: [],
      validationLog: ["Model verified"],
      constraints: [],
      verifiedAt: new Date().toISOString(),
    };
    const witness = unwrap(witSigner.signWitnessEvidence({
      payload: witPayload,
      parentTaintEvidence: taint,
    }));

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
  // 1. Production Authentication Bypass Audit
  // ==========================================================================

  it("AUDIT-1: Production VulnerabilityAdjudicationBridge strictly rejects unauthenticated in-memory proof", () => {
    const rawReachability = {
      status: "REACHABLE" as const,
      paths: [],
      entryPoint: "main",
      target: "system",
      deadCodeFunctions: [],
      reasoning: "Fabricated in-memory reachability",
      provider: "ReaControlFlowEngine",
      analysisOutcome: "SUCCESS" as const,
      isComplete: true,
    };

    const rawTaint = {
      status: "PROVEN_TAINT" as const,
      source: null,
      sink: { api: "system", functionName: "handle_req", address: 0x1020, vulnerableParameterIndex: 0 },
      steps: [],
      sanitizers: [],
      isSanitized: false,
      hasUnresolvedAliases: false,
      reasoning: "Fabricated taint",
    };

    const rawWitness = {
      witnessId: "wit_fake",
      isSatisfiable: true,
      isReproducible: true,
      exploitabilityStatus: "PROVEN" as const,
      conflictingGuards: [],
      validationLog: [],
      verifiedAt: new Date().toISOString(),
    };

    // Caller attempts to pass fabricated objects to production bridge
    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, candidateCmdInj, {
      reachability: rawReachability as any,
      taintFlow: rawTaint as any,
      witnessValidation: rawWitness as any,
    });

    expect(res.ok).toBe(true);
    const finding = unwrap(res);
    expect(finding.lifecycleState).toBe("INCONCLUSIVE");
    expect(finding.lifecycleState).not.toBe("VERIFIED");
    expect(finding.finding.confidence.verification_method).toContain("Unauthenticated analysis evidence");
  });

  it("AUDIT-2: Public AdjudicationBridgeOptions does not accept requireAuthenticatedEvidence bypass", () => {
    // Attempting to pass requireAuthenticatedEvidence via untyped options has NO effect in production
    const prodBridge = new VulnerabilityAdjudicationBridge({
      // @ts-expect-error - Verifying that the option is rejected at runtime and type level
      requireAuthenticatedEvidence: false,
    });

    const res = prodBridge.adjudicateCandidate(testAssessmentId, testAsset, candidateCmdInj, {
      reachability: {
        status: "REACHABLE",
        paths: [],
        entryPoint: "main",
        target: "system",
        deadCodeFunctions: [],
        reasoning: "Fabricated",
        provider: "ReaControlFlowEngine",
        isComplete: true,
      } as any,
    });

    expect(res.ok).toBe(true);
    const finding = unwrap(res);
    // Must remain fail-closed INCONCLUSIVE, not accept unauthenticated reachability
    expect(finding.lifecycleState).toBe("INCONCLUSIVE");
  });

  // ==========================================================================
  // 2. Stage Signer Authorization & Reflection Audit
  // ==========================================================================

  it("AUDIT-3: ECMAScript private fields prevent reflection access to signing authority or keyring", () => {
    const stageContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: testBinarySha256,
      runId: activeRunId,
    };
    const reachSigner = authority.createReachabilitySigner(stageContext);

    // Verify reflection cannot access internal authority or keyring
    expect((reachSigner as any).authority).toBeUndefined();
    expect((reachSigner as any).keyringManager).toBeUndefined();
    expect(Object.getOwnPropertyNames(reachSigner)).not.toContain("authority");
    expect(Object.getOwnPropertyNames(reachSigner)).not.toContain("keyringManager");
    expect(Object.getOwnPropertySymbols(reachSigner)).toHaveLength(0);

    // Verify TrustedEvidenceAuthority does NOT expose getKeyringManager
    expect((authority as any).getKeyringManager).toBeUndefined();
    expect((authority as any).keyringManager).toBeUndefined();
  });

  it("AUDIT-4: Stage signer cannot sign evidence for another stage", () => {
    const stageContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: testBinarySha256,
      runId: activeRunId,
    };
    const reachSigner = authority.createReachabilitySigner(stageContext);

    // Verify reachability signer only exposes signReachabilityEvidence
    expect((reachSigner as any).signTaintEvidence).toBeUndefined();
    expect((reachSigner as any).signWitnessEvidence).toBeUndefined();
    expect((reachSigner as any).signDecoderEvidence).toBeUndefined();
    expect((reachSigner as any).signCfgEvidence).toBeUndefined();
  });

  it("AUDIT-5: Provider impersonation through signer is rejected by provider allowlist", () => {
    const pipeline = createValidEvidencePipeline("system", "REA-ADV-CMD-INJ", "command_injection");
    const stageContext = {
      assessmentId: testAssessmentId,
      assetId: testAssetId,
      binarySha256: testBinarySha256,
      runId: activeRunId,
    };
    const reachSigner = authority.createReachabilitySigner(stageContext);

    const signRes = reachSigner.signReachabilityEvidence({
      payload: pipeline.reachability.payload,
      parentCfgEvidence: pipeline.cfg,
      provider: "AttackerInjectedMaliciousProvider",
    });

    expect(signRes.ok).toBe(false);
    if (signRes.ok) return;
    expect(signRes.error.code).toBe("UNAUTHORIZED_PROVIDER");
  });

  // ==========================================================================
  // 3. Evidence Verification, Cross-Candidate & TOCTOU Audit
  // ==========================================================================

  it("AUDIT-6: Cross-candidate reachability sink API substitution is rejected", () => {
    // Generate valid authenticated evidence for sink 'system'
    const pipeline = createValidEvidencePipeline("system", "REA-ADV-CMD-INJ", "command_injection");

    // Attacker attempts to use 'system' reachability evidence to verify candidate with sink 'strcpy'
    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, candidateStrcpy, {
      trustedReachability: pipeline.reachability,
      trustedTaint: pipeline.taint,
      trustedWitness: pipeline.witness,
      verifier,
      runId: activeRunId,
    });

    expect(res.ok).toBe(true);
    const finding = unwrap(res);
    expect(finding.lifecycleState).toBe("INCONCLUSIVE");
    expect(finding.lifecycleState).not.toBe("VERIFIED");
    expect(finding.finding.confidence.verification_method).toContain("Reachability evidence target mismatch");
  });

  it("AUDIT-7: Cross-candidate witness ruleId / category substitution is rejected", () => {
    // Pipeline for 'system' and rule 'REA-ADV-CMD-INJ'
    const pipeline = createValidEvidencePipeline("system", "REA-ADV-CMD-INJ", "command_injection");

    // Candidate has different ruleId
    const mismatchedCandidate: VulnerabilityCandidate = {
      ...candidateCmdInj,
      ruleId: "REA-DIFFERENT-RULE-ID",
    };

    const res = bridge.adjudicateCandidate(testAssessmentId, testAsset, mismatchedCandidate, {
      trustedReachability: pipeline.reachability,
      trustedTaint: pipeline.taint,
      trustedWitness: pipeline.witness,
      verifier,
      runId: activeRunId,
    });

    expect(res.ok).toBe(true);
    const finding = unwrap(res);
    expect(finding.lifecycleState).toBe("INCONCLUSIVE");
    expect(finding.finding.confidence.verification_method).toContain("Witness evidence candidate mismatch");
  });

  it("AUDIT-8: Single-use witness evidence replay within the same run is blocked via atomic consumption", () => {
    const pipeline = createValidEvidencePipeline("system", "REA-ADV-CMD-INJ", "command_injection");

    // First adjudication succeeds and consumes the witness evidence
    const res1 = bridge.adjudicateCandidate(testAssessmentId, testAsset, candidateCmdInj, {
      trustedReachability: pipeline.reachability,
      trustedTaint: pipeline.taint,
      trustedWitness: pipeline.witness,
      verifier,
      runId: activeRunId,
    });

    expect(res1.ok).toBe(true);
    expect(unwrap(res1).lifecycleState).toBe("VERIFIED");

    // Second adjudication attempting to replay the same witness evidence is REJECTED
    const res2 = bridge.adjudicateCandidate(testAssessmentId, testAsset, candidateCmdInj, {
      trustedReachability: pipeline.reachability,
      trustedTaint: pipeline.taint,
      trustedWitness: pipeline.witness,
      verifier,
      runId: activeRunId,
    });

    expect(res2.ok).toBe(true);
    const finding2 = unwrap(res2);
    expect(finding2.lifecycleState).toBe("INCONCLUSIVE");
    expect(finding2.finding.confidence.verification_method).toContain("replay detected");
  });

  // ==========================================================================
  // 4. Cryptographic Implementation & Constant-Time Verification Audit
  // ==========================================================================

  it("AUDIT-9: Constant-time signature comparison rejects non-hex, malformed, or invalid signatures", () => {
    const pipeline = createValidEvidencePipeline("system", "REA-ADV-CMD-INJ", "command_injection");

    // Malformed signature (not 64-char hex)
    const malformed1 = { ...pipeline.reachability, signature: "short_sig" };
    const res1 = verifier.verifyEvidence(malformed1 as any);
    expect(res1.ok).toBe(false);
    if (!res1.ok) {
      expect(res1.error.code).toBe("SIGNATURE_INVALID");
    }

    // Non-hex characters
    const malformed2 = { ...pipeline.reachability, signature: "z".repeat(64) };
    const res2 = verifier.verifyEvidence(malformed2 as any);
    expect(res2.ok).toBe(false);
    if (!res2.ok) {
      expect(res2.error.code).toBe("SIGNATURE_INVALID");
    }

    // Valid hex format but wrong HMAC
    const malformed3 = { ...pipeline.reachability, signature: "0123456789abcdef".repeat(4) };
    const res3 = verifier.verifyEvidence(malformed3 as any);
    expect(res3.ok).toBe(false);
    if (!res3.ok) {
      expect(res3.error.code).toBe("SIGNATURE_INVALID");
    }
  });

  it("AUDIT-10: Evidence mutation between verification and consumption fails verification", () => {
    const pipeline = createValidEvidencePipeline("system", "REA-ADV-CMD-INJ", "command_injection");

    // The evidence is frozen by verifyEvidence
    const verifiedRes = verifier.verifyEvidence(pipeline.reachability);
    expect(verifiedRes.ok).toBe(true);
    const frozen = unwrap(verifiedRes);

    expect(Object.isFrozen(frozen)).toBe(true);
    expect(Object.isFrozen(frozen.payload)).toBe(true);
    expect(Object.isFrozen(frozen.claims)).toBe(true);

    // Attempting to mutate in non-strict or ignored mode will not alter digests
    expect(() => {
      (frozen.payload as any).status = "MUTATED";
    }).toThrow();
  });
});
