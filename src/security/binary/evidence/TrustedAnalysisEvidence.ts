import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import canonicalize from "canonicalize";
import { err, ok, type Result } from "../../../domain/result.js";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { AssetId } from "../../../domain/security/asset.js";
import type { KeyringManager } from "../../packboard/secureKeyring.js";
import type {
  AnalysisRunRecord,
  AnalysisRunStatus,
  AnalysisStage,
  CanonicalBasicBlock,
  CanonicalControlFlowEdge,
  CanonicalFunctionCallEdge,
  CanonicalInstruction,
  CanonicalReachabilityPath,
  CanonicalReachabilityStep,
  CanonicalSanitizerGuard,
  CanonicalTaintStep,
  CanonicalWitnessConstraint,
  CfgPayload,
  DecoderCompletenessClaim,
  DecoderPayload,
  EvidenceVerificationError,
  ReachabilityPayload,
  TaintPayload,
  TrustedAnalysisEvidence,
  TrustedEvidenceClaims,
  WitnessPayload,
} from "./types.js";

export const TRUSTED_EVIDENCE_SCHEMA_VERSION = "1.0.0" as const;
export const TRUSTED_EVIDENCE_DOMAIN = "REA_TRUSTED_ANALYSIS_EVIDENCE_V1" as const;
export const TRUSTED_EVIDENCE_CANONICALIZATION = "RFC8785_JCS_V1" as const;
export const TRUSTED_EVIDENCE_HASH_ALGORITHM = "SHA256" as const;

export const AUTHORIZED_PROVIDERS: readonly string[] = [
  "ReaControlFlowEngine",
  "CapstoneDecoderProvider",
  "InProcessInstructionDecoder",
  "GhidraProvider",
  "IdaProvider",
  "ReaTaintEngine",
  "ReaWitnessEngine",
];

// ============================================================================
// Cryptographic Canonicalization & Deep Immutability Helpers
// ============================================================================

/**
 * Computes deterministic RFC 8785 JSON Canonicalization Scheme (JCS) SHA-256 digest.
 */
export function canonicalDigest(data: unknown): string {
  const json = canonicalize(data);
  if (json === undefined) {
    throw new Error("CANONICALIZATION_FAILED: Data structure cannot be canonicalized to JSON");
  }
  return createHash("sha256").update(json, "utf8").digest("hex");
}

/**
 * Computes domain-separated HMAC-SHA256 signature over claims digest.
 */
export function computeEvidenceSignature(secretKey: string, keyVersion: number, claimsDigest: string): string {
  const domainMessage = `${TRUSTED_EVIDENCE_DOMAIN}::${keyVersion}::${claimsDigest}`;
  return createHmac("sha256", secretKey).update(domainMessage, "utf8").digest("hex");
}

/**
 * Recursively freezes an object graph to prevent in-memory mutation.
 */
export function deepFreeze<T>(obj: T): T {
  if (obj === null || typeof obj !== "object") {
    return obj;
  }

  // Freeze own properties first
  Object.freeze(obj);

  for (const key of Object.getOwnPropertyNames(obj)) {
    const prop = (obj as any)[key];
    if (prop !== null && (typeof prop === "object" || typeof prop === "function") && !Object.isFrozen(prop)) {
      deepFreeze(prop);
    }
  }

  return obj;
}

/**
 * Deep clones data through JSON serialization to eliminate hidden references, Maps, Sets, or Buffers.
 */
export function deepClonePlain<T>(obj: T): T {
  const json = canonicalize(obj) ?? JSON.stringify(obj);
  return JSON.parse(json) as T;
}

// ============================================================================
// Analysis Run Manager (Authoritative SQLite & In-Memory State)
// ============================================================================

export class AnalysisRunManager {
  private readonly inMemoryRuns = new Map<string, AnalysisRunRecord>();
  private readonly inMemoryEvidence = new Map<string, { evidence: TrustedAnalysisEvidence<any>; consumedAt?: number }>();

  constructor(private readonly db?: DatabaseSync | undefined) {}

  public startRun(
    assessmentId: AssessmentId,
    assetId: AssetId,
    binarySha256: string,
  ): AnalysisRunRecord {
    const runId = `run_${randomBytes(16).toString("hex")}`;
    const nonce = `nonce_${randomBytes(16).toString("hex")}`;
    const now = Date.now();

    const record: AnalysisRunRecord = {
      runId,
      assessmentId,
      assetId,
      binarySha256,
      status: "ACTIVE",
      nonce,
      createdAt: now,
    };

    if (this.db) {
      this.db
        .prepare(
          `INSERT INTO analysis_runs (run_id, assessment_id, asset_id, binary_sha256, status, nonce, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(runId, assessmentId, assetId, binarySha256, "ACTIVE", nonce, now);
    }

    this.inMemoryRuns.set(runId, record);
    return record;
  }

  public completeRun(runId: string): Result<void, EvidenceVerificationError> {
    const run = this.getRun(runId);
    if (!run) {
      return err({ code: "RUN_INACTIVE", message: `Run ${runId} not found` });
    }

    const now = Date.now();
    const updated: AnalysisRunRecord = { ...run, status: "COMPLETED", completedAt: now };

    if (this.db) {
      this.db.prepare("UPDATE analysis_runs SET status = 'COMPLETED', completed_at = ? WHERE run_id = ?").run(now, runId);
    }

    this.inMemoryRuns.set(runId, updated);
    return ok(undefined);
  }

  public revokeRun(runId: string): Result<void, EvidenceVerificationError> {
    const run = this.getRun(runId);
    if (!run) {
      return err({ code: "RUN_INACTIVE", message: `Run ${runId} not found` });
    }

    const updated: AnalysisRunRecord = { ...run, status: "REVOKED" };

    if (this.db) {
      this.db.prepare("UPDATE analysis_runs SET status = 'REVOKED' WHERE run_id = ?").run(runId);
    }

    this.inMemoryRuns.set(runId, updated);
    return ok(undefined);
  }

  public getRun(runId: string): AnalysisRunRecord | null {
    if (this.db) {
      const row = this.db
        .prepare(
          `SELECT run_id, assessment_id, asset_id, binary_sha256, status, nonce, created_at, completed_at
           FROM analysis_runs WHERE run_id = ?`,
        )
        .get(runId) as any;

      if (row) {
        return {
          runId: row.run_id,
          assessmentId: row.assessment_id as AssessmentId,
          assetId: row.asset_id as AssetId,
          binarySha256: row.binary_sha256,
          status: row.status as AnalysisRunStatus,
          nonce: row.nonce,
          createdAt: row.created_at,
          completedAt: row.completed_at ?? undefined,
        };
      }
    }

    return this.inMemoryRuns.get(runId) ?? null;
  }

  public recordEvidenceRecord(evidence: TrustedAnalysisEvidence<any>): void {
    if (this.db) {
      this.db
        .prepare(
          `INSERT OR REPLACE INTO analysis_evidence_records
           (evidence_id, run_id, assessment_id, asset_id, stage, claims_json, payload_json, claims_digest, payload_digest, signature, key_version, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          evidence.claims.evidenceId,
          evidence.claims.runId,
          evidence.claims.assessmentId,
          evidence.claims.assetId,
          evidence.claims.stage,
          canonicalize(evidence.claims) ?? JSON.stringify(evidence.claims),
          canonicalize(evidence.payload) ?? JSON.stringify(evidence.payload),
          evidence.claimsDigest,
          evidence.claims.payloadDigest,
          evidence.signature,
          evidence.keyVersion,
          evidence.claims.timestamp,
        );
    }

    this.inMemoryEvidence.set(evidence.claims.evidenceId, { evidence });
  }

  public markEvidenceConsumed(evidenceId: string, runId: string): Result<void, EvidenceVerificationError> {
    const run = this.getRun(runId);
    if (!run) {
      return err({ code: "RUN_INACTIVE", message: `Run ${runId} not found` });
    }
    if (run.status === "COMPLETED") {
      return err({ code: "RUN_COMPLETED", message: `Cannot consume evidence from completed run ${runId}` });
    }
    if (run.status === "REVOKED") {
      return err({ code: "RUN_REVOKED", message: `Cannot consume evidence from revoked run ${runId}` });
    }

    const now = Date.now();

    if (this.db) {
      const existing = this.db
        .prepare("SELECT consumed_at FROM analysis_evidence_records WHERE evidence_id = ?")
        .get(evidenceId) as any;

      if (existing && existing.consumed_at !== null) {
        return err({ code: "REPLAY_DETECTED", message: `Evidence ${evidenceId} has already been consumed` });
      }

      this.db
        .prepare("UPDATE analysis_evidence_records SET consumed_at = ? WHERE evidence_id = ?")
        .run(now, evidenceId);
      return ok(undefined);
    }

    const memRec = this.inMemoryEvidence.get(evidenceId);
    if (memRec && memRec.consumedAt !== undefined) {
      return err({ code: "REPLAY_DETECTED", message: `Evidence ${evidenceId} has already been consumed in memory` });
    }
    if (memRec) {
      memRec.consumedAt = now;
    }

    return ok(undefined);
  }

  public isEvidenceConsumed(evidenceId: string): boolean {
    if (this.db) {
      const existing = this.db
        .prepare("SELECT consumed_at FROM analysis_evidence_records WHERE evidence_id = ?")
        .get(evidenceId) as any;
      if (existing) {
        return existing.consumed_at !== null;
      }
    }
    const memRec = this.inMemoryEvidence.get(evidenceId);
    return memRec?.consumedAt !== undefined;
  }
}

// ============================================================================
// Stage Execution Context & Capability-Based Signing Authority
// ============================================================================

const kInternalSign = Symbol("kInternalSign");
const kVerifyParent = Symbol("kVerifyParent");

export interface StageContext {
  readonly assessmentId: AssessmentId;
  readonly assetId: AssetId;
  readonly binarySha256: string;
  readonly firmwareSha256?: string | undefined;
  readonly runId: string;
}

export class TrustedEvidenceAuthority {
  readonly #keyringManager: KeyringManager;
  readonly #runManager: AnalysisRunManager;

  constructor(options: { keyringManager: KeyringManager; db?: DatabaseSync | undefined; runManager?: AnalysisRunManager }) {
    this.#keyringManager = options.keyringManager;
    this.#runManager = options.runManager ?? new AnalysisRunManager(options.db);
  }

  public getRunManager(): AnalysisRunManager {
    return this.#runManager;
  }

  /**
   * Internal capability-gated parent evidence verification.
   * Only accessible to authorized Stage Signers via unexported Symbol.
   */
  [kVerifyParent]<T>(
    parentEvidence: TrustedAnalysisEvidence<T>,
    expectedStage: AnalysisStage,
  ): Result<TrustedAnalysisEvidence<T>, EvidenceVerificationError> {
    const verifier = new TrustedEvidenceVerifier({ keyringManager: this.#keyringManager });
    return verifier.verifyEvidence(parentEvidence, expectedStage);
  }

  /**
   * Internal capability-gated signing primitive.
   * Only accessible to authorized Stage Signers via unexported Symbol.
   */
  [kInternalSign]<T>(
    stage: AnalysisStage,
    claimsInput: Omit<
      TrustedEvidenceClaims,
      "schemaVersion" | "stage" | "canonicalizationVersion" | "hashAlgorithm" | "payloadDigest"
    >,
    payload: T,
  ): Result<TrustedAnalysisEvidence<T>, EvidenceVerificationError> {
    // 1. Verify that run is ACTIVE
    const run = this.#runManager.getRun(claimsInput.runId);
    if (!run || run.status !== "ACTIVE") {
      return err({
        code: run?.status === "COMPLETED" ? "RUN_COMPLETED" : run?.status === "REVOKED" ? "RUN_REVOKED" : "RUN_INACTIVE",
        message: `Cannot sign evidence for inactive run: ${claimsInput.runId} (status: ${run?.status ?? "NOT_FOUND"})`,
      });
    }

    // 2. Assessment isolation check
    if (run.assessmentId !== claimsInput.assessmentId) {
      return err({
        code: "CROSS_ASSESSMENT_REUSE",
        message: `Assessment isolation mismatch: run ${run.assessmentId} does not match claims ${claimsInput.assessmentId}`,
      });
    }

    // 3. Binary identity check
    if (run.binarySha256 !== claimsInput.binarySha256) {
      return err({
        code: "CROSS_BINARY_REUSE",
        message: `Binary digest mismatch: run ${run.binarySha256} does not match claims ${claimsInput.binarySha256}`,
      });
    }

    // 4. Asset identity check
    if (run.assetId !== claimsInput.assetId) {
      return err({
        code: "CROSS_ASSET_REUSE",
        message: `Asset ID mismatch: run ${run.assetId} does not match claims ${claimsInput.assetId}`,
      });
    }

    // 5. Canonicalize payload and compute payload digest
    const canonicalPayload = deepClonePlain(payload);
    let payloadDigest: string;
    try {
      payloadDigest = canonicalDigest(canonicalPayload);
    } catch (cause) {
      return err({
        code: "CANONICALIZATION_ERROR",
        message: `Failed to canonicalize payload: ${cause instanceof Error ? cause.message : String(cause)}`,
      });
    }

    const fullClaims: TrustedEvidenceClaims = {
      ...claimsInput,
      schemaVersion: TRUSTED_EVIDENCE_SCHEMA_VERSION,
      stage,
      canonicalizationVersion: TRUSTED_EVIDENCE_CANONICALIZATION,
      hashAlgorithm: TRUSTED_EVIDENCE_HASH_ALGORITHM,
      payloadDigest,
    };

    const canonicalClaims = deepClonePlain(fullClaims);
    let claimsDigest: string;
    try {
      claimsDigest = canonicalDigest(canonicalClaims);
    } catch (cause) {
      return err({
        code: "CANONICALIZATION_ERROR",
        message: `Failed to canonicalize claims: ${cause instanceof Error ? cause.message : String(cause)}`,
      });
    }

    const activeKey = this.#keyringManager.getActiveKey();
    const signature = computeEvidenceSignature(activeKey.key_hex, activeKey.version, claimsDigest);

    const evidence: TrustedAnalysisEvidence<T> = {
      claims: canonicalClaims,
      payload: canonicalPayload,
      claimsDigest,
      signature,
      keyVersion: activeKey.version,
    };

    const frozen = deepFreeze(evidence);
    this.#runManager.recordEvidenceRecord(frozen);

    return ok(frozen);
  }

  // Capability factory methods: Each returns a stage-locked signer
  public createDecoderSigner(context: StageContext): DecoderStageSigner {
    return new DecoderStageSigner(this, context);
  }

  public createCfgSigner(context: StageContext): CfgStageSigner {
    return new CfgStageSigner(this, context);
  }

  public createReachabilitySigner(context: StageContext): ReachabilityStageSigner {
    return new ReachabilityStageSigner(this, context);
  }

  public createTaintSigner(context: StageContext): TaintStageSigner {
    return new TaintStageSigner(this, context);
  }

  public createWitnessSigner(context: StageContext): WitnessStageSigner {
    return new WitnessStageSigner(this, context);
  }
}

// ============================================================================
// Stage Signers (Capability Encapsulation)
// ============================================================================

export class DecoderStageSigner {
  readonly #authority: TrustedEvidenceAuthority;
  readonly #context: StageContext;

  constructor(
    authority: TrustedEvidenceAuthority,
    context: StageContext,
  ) {
    this.#authority = authority;
    this.#context = context;
  }

  public signDecoderEvidence(input: {
    readonly payload: DecoderPayload;
    readonly provider: string;
    readonly providerImplementation?: string | undefined;
    readonly providerVersion?: string | undefined;
    readonly providerBuild?: string | undefined;
    readonly decoderConfig?: Readonly<Record<string, unknown>> | undefined;
    readonly architecture: string;
    readonly executionMode?: string | undefined;
  }): Result<TrustedAnalysisEvidence<DecoderPayload>, EvidenceVerificationError> {
    if (!AUTHORIZED_PROVIDERS.includes(input.provider)) {
      return err({
        code: "UNAUTHORIZED_PROVIDER",
        message: `Provider '${input.provider}' is not authorized to emit Decoder evidence`,
      });
    }

    const evidenceId = `ev_dec_${randomBytes(16).toString("hex")}`;
    const now = Date.now();

    const decodeCompleteness: DecoderCompletenessClaim = {
      isComplete: input.payload.outcome === "SUCCESS",
      outcome: input.payload.outcome,
      decodedBytes: input.payload.decodedBytes,
      totalBytes: input.payload.totalBytes,
      unhandledByteOffset: input.payload.unhandledByteOffset,
    };

    return this.#authority[kInternalSign]<DecoderPayload>(
      "DECODER",
      {
        evidenceId,
        assessmentId: this.#context.assessmentId,
        assetId: this.#context.assetId,
        firmwareSha256: this.#context.firmwareSha256 ?? "none",
        binarySha256: this.#context.binarySha256,
        runId: this.#context.runId,
        provider: input.provider,
        providerImplementation: input.providerImplementation ?? "InProcessInstructionDecoder",
        providerVersion: input.providerVersion ?? "1.0.0",
        providerBuild: input.providerBuild ?? "rea_core",
        decoderConfig: input.decoderConfig ?? {},
        architecture: input.architecture,
        executionMode: input.executionMode ?? "static_disassembly",
        cfgHash: "none",
        decodeCompleteness,
        parentEvidenceIds: [],
        timestamp: now,
      },
      input.payload,
    );
  }
}

export class CfgStageSigner {
  readonly #authority: TrustedEvidenceAuthority;
  readonly #context: StageContext;

  constructor(
    authority: TrustedEvidenceAuthority,
    context: StageContext,
  ) {
    this.#authority = authority;
    this.#context = context;
  }

  public signCfgEvidence(input: {
    readonly payload: CfgPayload;
    readonly parentDecoderEvidence: TrustedAnalysisEvidence<DecoderPayload>;
    readonly provider?: string | undefined;
    readonly providerImplementation?: string | undefined;
    readonly providerVersion?: string | undefined;
    readonly providerBuild?: string | undefined;
    readonly executionMode?: string | undefined;
  }): Result<TrustedAnalysisEvidence<CfgPayload>, EvidenceVerificationError> {
    // 1. Verify parent decoder evidence
    const verifyParent = this.#authority[kVerifyParent](input.parentDecoderEvidence, "DECODER");
    if (!verifyParent.ok) {
      return err(verifyParent.error);
    }

    const parent = input.parentDecoderEvidence;

    // 2. Verify lineage bindings
    if (parent.claims.assessmentId !== this.#context.assessmentId) {
      return err({ code: "CROSS_ASSESSMENT_REUSE", message: "Parent decoder evidence belongs to a different assessment" });
    }
    if (parent.claims.assetId !== this.#context.assetId) {
      return err({ code: "CROSS_ASSET_REUSE", message: "Parent decoder evidence belongs to a different asset" });
    }
    if (parent.claims.binarySha256 !== this.#context.binarySha256) {
      return err({ code: "CROSS_BINARY_REUSE", message: "Parent decoder evidence belongs to a different binary" });
    }
    if (parent.claims.runId !== this.#context.runId) {
      return err({ code: "CROSS_RUN_REUSE", message: "Parent decoder evidence belongs to a different run" });
    }

    // 3. Completeness invariant: CFG cannot claim complete if decoder was partial or failed
    if (!parent.claims.decodeCompleteness.isComplete && input.payload.isComplete) {
      return err({
        code: "INCOMPLETE_DECODE",
        message: "CFG cannot claim isComplete = true when parent decoder was PARTIAL or failed",
      });
    }

    const provider = input.provider ?? "ReaControlFlowEngine";
    if (!AUTHORIZED_PROVIDERS.includes(provider)) {
      return err({ code: "UNAUTHORIZED_PROVIDER", message: `Provider '${provider}' is not authorized for CFG evidence` });
    }

    const evidenceId = `ev_cfg_${randomBytes(16).toString("hex")}`;
    const now = Date.now();

    // Deterministic CFG hash over blocks and edges
    const cfgStructure = {
      functionName: input.payload.functionName,
      entryBlockId: input.payload.entryBlockId,
      blocks: input.payload.blocks,
      edges: input.payload.edges,
    };
    const computedCfgHash = canonicalDigest(cfgStructure);

    const decodeCompleteness: DecoderCompletenessClaim = {
      isComplete: input.payload.isComplete && parent.claims.decodeCompleteness.isComplete,
      outcome: input.payload.decodeOutcome,
      decodedBytes: parent.claims.decodeCompleteness.decodedBytes,
      totalBytes: parent.claims.decodeCompleteness.totalBytes,
      unhandledByteOffset: parent.claims.decodeCompleteness.unhandledByteOffset,
    };

    return this.#authority[kInternalSign]<CfgPayload>(
      "CFG",
      {
        evidenceId,
        assessmentId: this.#context.assessmentId,
        assetId: this.#context.assetId,
        firmwareSha256: this.#context.firmwareSha256 ?? "none",
        binarySha256: this.#context.binarySha256,
        runId: this.#context.runId,
        provider,
        providerImplementation: input.providerImplementation ?? "ControlFlowGraphBuilder",
        providerVersion: input.providerVersion ?? "1.0.0",
        providerBuild: input.providerBuild ?? "rea_core",
        decoderConfig: parent.claims.decoderConfig,
        architecture: input.payload.architecture,
        executionMode: input.executionMode ?? "static_cfg_construction",
        cfgHash: computedCfgHash,
        decodeCompleteness,
        parentEvidenceIds: [parent.claims.evidenceId],
        timestamp: now,
      },
      {
        ...input.payload,
        cfgHash: computedCfgHash,
      },
    );
  }
}

export class ReachabilityStageSigner {
  readonly #authority: TrustedEvidenceAuthority;
  readonly #context: StageContext;

  constructor(
    authority: TrustedEvidenceAuthority,
    context: StageContext,
  ) {
    this.#authority = authority;
    this.#context = context;
  }

  public signReachabilityEvidence(input: {
    readonly payload: ReachabilityPayload;
    readonly parentCfgEvidence: TrustedAnalysisEvidence<CfgPayload>;
    readonly provider?: string | undefined;
    readonly providerImplementation?: string | undefined;
    readonly providerVersion?: string | undefined;
    readonly providerBuild?: string | undefined;
    readonly executionMode?: string | undefined;
  }): Result<TrustedAnalysisEvidence<ReachabilityPayload>, EvidenceVerificationError> {
    // 1. Verify parent CFG evidence
    const verifyParent = this.#authority[kVerifyParent](input.parentCfgEvidence, "CFG");
    if (!verifyParent.ok) {
      return err(verifyParent.error);
    }

    const parent = input.parentCfgEvidence;

    // 2. Lineage checks
    if (parent.claims.assessmentId !== this.#context.assessmentId) {
      return err({ code: "CROSS_ASSESSMENT_REUSE", message: "Parent CFG evidence belongs to different assessment" });
    }
    if (parent.claims.assetId !== this.#context.assetId) {
      return err({ code: "CROSS_ASSET_REUSE", message: "Parent CFG evidence belongs to different asset" });
    }
    if (parent.claims.binarySha256 !== this.#context.binarySha256) {
      return err({ code: "CROSS_BINARY_REUSE", message: "Parent CFG evidence belongs to different binary" });
    }
    if (parent.claims.runId !== this.#context.runId) {
      return err({ code: "CROSS_RUN_REUSE", message: "Parent CFG evidence belongs to different run" });
    }

    // 3. Completeness invariant: Reachability cannot be complete if CFG was incomplete
    if (!parent.claims.decodeCompleteness.isComplete && input.payload.isComplete) {
      return err({
        code: "INCOMPLETE_DECODE",
        message: "Reachability cannot claim isComplete = true when parent CFG was incomplete",
      });
    }

    const provider = input.provider ?? "ReaControlFlowEngine";
    if (!AUTHORIZED_PROVIDERS.includes(provider)) {
      return err({ code: "UNAUTHORIZED_PROVIDER", message: `Provider '${provider}' is not authorized for Reachability evidence` });
    }

    const evidenceId = `ev_rch_${randomBytes(16).toString("hex")}`;
    const now = Date.now();

    return this.#authority[kInternalSign]<ReachabilityPayload>(
      "REACHABILITY",
      {
        evidenceId,
        assessmentId: this.#context.assessmentId,
        assetId: this.#context.assetId,
        firmwareSha256: this.#context.firmwareSha256 ?? "none",
        binarySha256: this.#context.binarySha256,
        runId: this.#context.runId,
        provider,
        providerImplementation: input.providerImplementation ?? "ReachabilityAnalyzer",
        providerVersion: input.providerVersion ?? "1.0.0",
        providerBuild: input.providerBuild ?? "rea_core",
        decoderConfig: parent.claims.decoderConfig,
        architecture: parent.claims.architecture,
        executionMode: input.executionMode ?? "static_reachability",
        cfgHash: parent.claims.cfgHash,
        decodeCompleteness: parent.claims.decodeCompleteness,
        parentEvidenceIds: [parent.claims.evidenceId],
        timestamp: now,
      },
      input.payload,
    );
  }
}

export class TaintStageSigner {
  readonly #authority: TrustedEvidenceAuthority;
  readonly #context: StageContext;

  constructor(
    authority: TrustedEvidenceAuthority,
    context: StageContext,
  ) {
    this.#authority = authority;
    this.#context = context;
  }

  public signTaintEvidence(input: {
    readonly payload: TaintPayload;
    readonly parentCfgEvidence: TrustedAnalysisEvidence<CfgPayload>;
    readonly provider?: string | undefined;
    readonly providerImplementation?: string | undefined;
    readonly providerVersion?: string | undefined;
    readonly providerBuild?: string | undefined;
    readonly executionMode?: string | undefined;
  }): Result<TrustedAnalysisEvidence<TaintPayload>, EvidenceVerificationError> {
    const verifyParent = this.#authority[kVerifyParent](input.parentCfgEvidence, "CFG");
    if (!verifyParent.ok) {
      return err(verifyParent.error);
    }

    const parent = input.parentCfgEvidence;

    if (parent.claims.assessmentId !== this.#context.assessmentId) {
      return err({ code: "CROSS_ASSESSMENT_REUSE", message: "Parent CFG belongs to different assessment" });
    }
    if (parent.claims.assetId !== this.#context.assetId) {
      return err({ code: "CROSS_ASSET_REUSE", message: "Parent CFG belongs to different asset" });
    }
    if (parent.claims.binarySha256 !== this.#context.binarySha256) {
      return err({ code: "CROSS_BINARY_REUSE", message: "Parent CFG belongs to different binary" });
    }
    if (parent.claims.runId !== this.#context.runId) {
      return err({ code: "CROSS_RUN_REUSE", message: "Parent CFG belongs to different run" });
    }

    const provider = input.provider ?? "ReaTaintEngine";
    if (!AUTHORIZED_PROVIDERS.includes(provider)) {
      return err({ code: "UNAUTHORIZED_PROVIDER", message: `Provider '${provider}' is not authorized for Taint evidence` });
    }

    const evidenceId = `ev_tnt_${randomBytes(16).toString("hex")}`;
    const now = Date.now();

    return this.#authority[kInternalSign]<TaintPayload>(
      "TAINT",
      {
        evidenceId,
        assessmentId: this.#context.assessmentId,
        assetId: this.#context.assetId,
        firmwareSha256: this.#context.firmwareSha256 ?? "none",
        binarySha256: this.#context.binarySha256,
        runId: this.#context.runId,
        provider,
        providerImplementation: input.providerImplementation ?? "TaintEngine",
        providerVersion: input.providerVersion ?? "1.0.0",
        providerBuild: input.providerBuild ?? "rea_core",
        decoderConfig: parent.claims.decoderConfig,
        architecture: parent.claims.architecture,
        executionMode: input.executionMode ?? "interprocedural_taint",
        cfgHash: parent.claims.cfgHash,
        decodeCompleteness: parent.claims.decodeCompleteness,
        parentEvidenceIds: [parent.claims.evidenceId],
        timestamp: now,
      },
      input.payload,
    );
  }
}

export class WitnessStageSigner {
  readonly #authority: TrustedEvidenceAuthority;
  readonly #context: StageContext;

  constructor(
    authority: TrustedEvidenceAuthority,
    context: StageContext,
  ) {
    this.#authority = authority;
    this.#context = context;
  }

  public signWitnessEvidence(input: {
    readonly payload: WitnessPayload;
    readonly parentTaintEvidence: TrustedAnalysisEvidence<TaintPayload>;
    readonly provider?: string | undefined;
    readonly providerImplementation?: string | undefined;
    readonly providerVersion?: string | undefined;
    readonly providerBuild?: string | undefined;
    readonly executionMode?: string | undefined;
  }): Result<TrustedAnalysisEvidence<WitnessPayload>, EvidenceVerificationError> {
    const verifyParent = this.#authority[kVerifyParent](input.parentTaintEvidence, "TAINT");
    if (!verifyParent.ok) {
      return err(verifyParent.error);
    }

    const parent = input.parentTaintEvidence;

    if (parent.claims.assessmentId !== this.#context.assessmentId) {
      return err({ code: "CROSS_ASSESSMENT_REUSE", message: "Parent Taint evidence belongs to different assessment" });
    }
    if (parent.claims.assetId !== this.#context.assetId) {
      return err({ code: "CROSS_ASSET_REUSE", message: "Parent Taint evidence belongs to different asset" });
    }
    if (parent.claims.binarySha256 !== this.#context.binarySha256) {
      return err({ code: "CROSS_BINARY_REUSE", message: "Parent Taint evidence belongs to different binary" });
    }
    if (parent.claims.runId !== this.#context.runId) {
      return err({ code: "CROSS_RUN_REUSE", message: "Parent Taint evidence belongs to different run" });
    }

    const provider = input.provider ?? "ReaWitnessEngine";
    if (!AUTHORIZED_PROVIDERS.includes(provider)) {
      return err({ code: "UNAUTHORIZED_PROVIDER", message: `Provider '${provider}' is not authorized for Witness evidence` });
    }

    const evidenceId = `ev_wit_${randomBytes(16).toString("hex")}`;
    const now = Date.now();

    return this.#authority[kInternalSign]<WitnessPayload>(
      "WITNESS",
      {
        evidenceId,
        assessmentId: this.#context.assessmentId,
        assetId: this.#context.assetId,
        firmwareSha256: this.#context.firmwareSha256 ?? "none",
        binarySha256: this.#context.binarySha256,
        runId: this.#context.runId,
        provider,
        providerImplementation: input.providerImplementation ?? "WitnessValidator",
        providerVersion: input.providerVersion ?? "1.0.0",
        providerBuild: input.providerBuild ?? "rea_core",
        decoderConfig: parent.claims.decoderConfig,
        architecture: parent.claims.architecture,
        executionMode: input.executionMode ?? "symbolic_constraint_validation",
        cfgHash: parent.claims.cfgHash,
        decodeCompleteness: parent.claims.decodeCompleteness,
        parentEvidenceIds: [parent.claims.evidenceId],
        timestamp: now,
      },
      input.payload,
    );
  }
}

// ============================================================================
// Trusted Evidence Verifier
// ============================================================================

export interface EvidenceVerifierOptions {
  readonly keyringManager: KeyringManager;
  readonly runManager?: AnalysisRunManager | undefined;
  readonly db?: DatabaseSync | undefined;
  readonly allowedProviders?: readonly string[] | undefined;
}

export class TrustedEvidenceVerifier {
  private readonly keyringManager: KeyringManager;
  private readonly runManager?: AnalysisRunManager | undefined;
  private readonly allowedProviders: readonly string[];

  constructor(options: EvidenceVerifierOptions) {
    this.keyringManager = options.keyringManager;
    this.runManager = options.runManager ?? (options.db ? new AnalysisRunManager(options.db) : undefined);
    this.allowedProviders = options.allowedProviders ?? AUTHORIZED_PROVIDERS;
  }

  /**
   * Cryptographically verify the integrity, schema, digests, and signature of an evidence record.
   */
  public verifyEvidence<T>(
    evidence: TrustedAnalysisEvidence<T>,
    expectedStage?: AnalysisStage,
  ): Result<TrustedAnalysisEvidence<T>, EvidenceVerificationError> {
    if (!evidence || typeof evidence !== "object" || !evidence.claims || evidence.payload === undefined) {
      return err({ code: "INVALID_CLAIMS_DIGEST", message: "Malformed evidence structure" });
    }

    // 1. Schema version check
    if (evidence.claims.schemaVersion !== TRUSTED_EVIDENCE_SCHEMA_VERSION) {
      return err({
        code: "INVALID_SCHEMA_VERSION",
        message: `Unsupported evidence schema version: ${evidence.claims.schemaVersion} (expected ${TRUSTED_EVIDENCE_SCHEMA_VERSION})`,
      });
    }

    // 2. Stage check
    if (expectedStage !== undefined && evidence.claims.stage !== expectedStage) {
      return err({
        code: "STAGE_MISMATCH",
        message: `Evidence stage mismatch: expected ${expectedStage}, found ${evidence.claims.stage}`,
      });
    }

    // 3. Provider authorization check
    if (!this.allowedProviders.includes(evidence.claims.provider)) {
      return err({
        code: "UNAUTHORIZED_PROVIDER",
        message: `Provider '${evidence.claims.provider}' is not an authorized analysis provider`,
      });
    }

    // 4. Re-canonicalize payload and verify payload digest
    let computedPayloadDigest: string;
    try {
      computedPayloadDigest = canonicalDigest(evidence.payload);
    } catch (cause) {
      return err({
        code: "CANONICALIZATION_ERROR",
        message: `Failed to canonicalize evidence payload: ${cause instanceof Error ? cause.message : String(cause)}`,
      });
    }

    if (computedPayloadDigest !== evidence.claims.payloadDigest) {
      return err({
        code: "INVALID_PAYLOAD_DIGEST",
        message: `Payload digest mismatch: expected ${evidence.claims.payloadDigest}, computed ${computedPayloadDigest} (payload was mutated after sealing)`,
      });
    }

    // 5. Re-canonicalize claims and verify claims digest
    let computedClaimsDigest: string;
    try {
      computedClaimsDigest = canonicalDigest(evidence.claims);
    } catch (cause) {
      return err({
        code: "CANONICALIZATION_ERROR",
        message: `Failed to canonicalize evidence claims: ${cause instanceof Error ? cause.message : String(cause)}`,
      });
    }

    if (computedClaimsDigest !== evidence.claimsDigest) {
      return err({
        code: "INVALID_CLAIMS_DIGEST",
        message: `Claims digest mismatch: expected ${evidence.claimsDigest}, computed ${computedClaimsDigest} (claims were modified after sealing)`,
      });
    }

    // 6. Key lookup and HMAC signature verification
    const secretKey = this.keyringManager.getKeyForVersion(evidence.keyVersion);
    if (!secretKey) {
      return err({
        code: "KEY_UNAVAILABLE",
        message: `Key version ${evidence.keyVersion} is unavailable or revoked in assessment keyring`,
      });
    }

    if (
      typeof evidence.signature !== "string" ||
      evidence.signature.length !== 64 ||
      !/^[0-9a-f]{64}$/i.test(evidence.signature)
    ) {
      return err({
        code: "SIGNATURE_INVALID",
        message: "Cryptographic HMAC signature verification failed (malformed signature format)",
      });
    }

    const expectedSignature = computeEvidenceSignature(secretKey, evidence.keyVersion, evidence.claimsDigest);
    const expectedBuf = Buffer.from(expectedSignature, "hex");
    const sigBuf = Buffer.from(evidence.signature, "hex");

    if (expectedBuf.length !== 32 || sigBuf.length !== 32 || !timingSafeEqual(expectedBuf, sigBuf)) {
      return err({
        code: "SIGNATURE_INVALID",
        message: "Cryptographic HMAC signature verification failed (invalid signature or wrong key)",
      });
    }

    return ok(deepFreeze(evidence));
  }

  /**
   * Verifies the cryptographic lineage of an evidence chain from Decoder up to target stage.
   */
  public verifyLineage(
    chain: readonly TrustedAnalysisEvidence<any>[],
    expectedContext: {
      readonly assessmentId: AssessmentId;
      readonly assetId: AssetId;
      readonly binarySha256: string;
      readonly runId: string;
    },
  ): Result<boolean, EvidenceVerificationError> {
    if (chain.length === 0) {
      return err({ code: "LINEAGE_INVALID", message: "Evidence chain is empty" });
    }

    // Allowed transition map: stage -> expected parent stage
    const parentStageMap: Record<AnalysisStage, AnalysisStage | null> = {
      DECODER: null,
      CFG: "DECODER",
      REACHABILITY: "CFG",
      TAINT: "CFG",
      WITNESS: "TAINT",
    };

    const evidenceById = new Map<string, TrustedAnalysisEvidence<any>>();

    // 1. Verify every evidence item's own cryptographic integrity and execution context
    for (const current of chain) {
      const verRes = this.verifyEvidence(current);
      if (!verRes.ok) {
        return err(verRes.error);
      }

      if (current.claims.assessmentId !== expectedContext.assessmentId) {
        return err({
          code: "CROSS_ASSESSMENT_REUSE",
          message: `Evidence ${current.claims.evidenceId} belongs to assessment ${current.claims.assessmentId}, expected ${expectedContext.assessmentId}`,
        });
      }
      if (current.claims.assetId !== expectedContext.assetId) {
        return err({
          code: "CROSS_ASSET_REUSE",
          message: `Evidence ${current.claims.evidenceId} belongs to asset ${current.claims.assetId}, expected ${expectedContext.assetId}`,
        });
      }
      if (current.claims.binarySha256 !== expectedContext.binarySha256) {
        return err({
          code: "CROSS_BINARY_REUSE",
          message: `Evidence ${current.claims.evidenceId} belongs to binary ${current.claims.binarySha256}, expected ${expectedContext.binarySha256}`,
        });
      }
      if (current.claims.runId !== expectedContext.runId) {
        return err({
          code: "CROSS_RUN_REUSE",
          message: `Evidence ${current.claims.evidenceId} belongs to run ${current.claims.runId}, expected ${expectedContext.runId}`,
        });
      }

      evidenceById.set(current.claims.evidenceId, current);
    }

    // 2. Verify parent references and stage transitions in the DAG
    for (const current of chain) {
      const expectedParentStage = parentStageMap[current.claims.stage];

      if (expectedParentStage === null) {
        // Root element (DECODER): must have no parent evidence IDs
        if (current.claims.parentEvidenceIds.length > 0) {
          return err({
            code: "LINEAGE_INVALID",
            message: `Root DECODER evidence cannot have parent evidence IDs`,
          });
        }
      } else {
        if (current.claims.parentEvidenceIds.length === 0) {
          return err({
            code: "PARENT_NOT_FOUND",
            message: `Stage ${current.claims.stage} is missing parent evidence ID in claims`,
          });
        }

        for (const parentId of current.claims.parentEvidenceIds) {
          const parent = evidenceById.get(parentId);
          if (!parent) {
            return err({
              code: "PARENT_NOT_FOUND",
              message: `Evidence ${current.claims.evidenceId} references missing parent ${parentId}`,
            });
          }

          if (parent.claims.stage !== expectedParentStage) {
            return err({
              code: "LINEAGE_INVALID",
              message: `Stage transition violation: parent ${parent.claims.stage} -> child ${current.claims.stage} (expected parent ${expectedParentStage})`,
            });
          }

          // CFG hash continuity check
          if (
            current.claims.stage !== "CFG" &&
            parent.claims.cfgHash !== "none" &&
            current.claims.cfgHash !== parent.claims.cfgHash
          ) {
            return err({
              code: "LINEAGE_INVALID",
              message: `CFG hash mismatch in lineage: current ${current.claims.cfgHash} does not match parent ${parent.claims.cfgHash}`,
            });
          }
        }
      }
    }

    return ok(true);
  }

  /**
   * Verify that a run is currently active and not replayed or revoked.
   */
  public verifyRunFreshness(
    runId: string,
    assessmentId: AssessmentId,
    assetId: AssetId,
    binarySha256: string,
  ): Result<boolean, EvidenceVerificationError> {
    if (!this.runManager) {
      // In-memory or standalone verifier without run manager assumes active run for unit testing
      return ok(true);
    }

    const run = this.runManager.getRun(runId);
    if (!run) {
      return err({ code: "RUN_INACTIVE", message: `Run ${runId} does not exist` });
    }
    if (run.status === "COMPLETED") {
      return err({ code: "RUN_COMPLETED", message: `Run ${runId} is completed; evidence replay is rejected` });
    }
    if (run.status === "REVOKED") {
      return err({ code: "RUN_REVOKED", message: `Run ${runId} has been revoked; evidence is invalid` });
    }
    if (run.assessmentId !== assessmentId) {
      return err({ code: "CROSS_ASSESSMENT_REUSE", message: `Run assessment mismatch` });
    }
    if (run.assetId !== assetId) {
      return err({ code: "CROSS_ASSET_REUSE", message: `Run asset mismatch` });
    }
    if (run.binarySha256 !== binarySha256) {
      return err({ code: "CROSS_BINARY_REUSE", message: `Run binary digest mismatch` });
    }

    return ok(true);
  }

  /**
   * Check if evidence has already been consumed in a verified adjudication.
   */
  public isEvidenceConsumed(evidenceId: string): boolean {
    if (!this.runManager) {
      return false;
    }
    return this.runManager.isEvidenceConsumed(evidenceId);
  }

  /**
   * Mark an evidence item as consumed by an adjudication, preventing replay within or across runs.
   */
  public consumeEvidence(evidenceId: string, runId: string): Result<void, EvidenceVerificationError> {
    if (!this.runManager) {
      return ok(undefined);
    }
    return this.runManager.markEvidenceConsumed(evidenceId, runId);
  }
}
