/* eslint-disable max-lines-per-function */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { err, ok, type Result } from "../../../domain/result.js";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { AssetId } from "../../../domain/security/asset.js";
import type { BlackboardAssetRecord } from "../../../domain/security/blackboard/types.js";
import type {
  FindingRecord,
  FindingState,
} from "../../../domain/security/blackboard/types.js";
import type {
  AdjudicatedFindingResult,
  VulnerabilityCandidate,
} from "../../../domain/security/binary/types.js";
import {
  BINARY_WORKER_PROTOCOL_VERSION,
  type BinaryWorkerAnalyzeResponse,
  type RawCandidate,
} from "../ipc/binaryWorkerProtocol.js";
import {
  AUTHORIZED_PROVIDERS,
  canonicalDigest,
  deepFreeze,
  TrustedEvidenceAuthority,
  type StageContext,
} from "./TrustedAnalysisEvidence.js";
import type {
  CfgPayload,
  DecoderPayload,
  EvidenceVerificationError,
  ReachabilityPayload,
  TaintPayload,
  TrustedAnalysisEvidence,
  WitnessPayload,
} from "./types.js";
import { VulnerabilityAdjudicationBridge } from "../VulnerabilityAdjudicationBridge.js";
import type { SqliteBlackboardStorage } from "../../blackboard/SqliteBlackboardStorage.js";

// ============================================================================
// Context & Error Interfaces
// ============================================================================

export interface ParentValidationContext {
  readonly assessmentId: AssessmentId;
  readonly assetId: AssetId;
  readonly binarySha256: string;
  readonly firmwareSha256?: string | undefined;
  readonly runId: string;
  readonly taskId: string;
  readonly fencingToken: number;
  readonly workerId: string;
  readonly workerInstanceId?: string | undefined;
  readonly requestedStage: string;
  readonly architecture: string;
  readonly binaryInputBytes?: Buffer | undefined;
  readonly binaryInputPath?: string | undefined;
  readonly allowedProviders?: readonly string[] | undefined;
}

export type ParentValidationErrorCode =
  | "CONTEXT_MISMATCH"
  | "INPUT_INTEGRITY_VIOLATION"
  | "SCHEMA_VIOLATION"
  | "STRUCTURAL_INCONSISTENCY"
  | "COMPLETENESS_CONTRADICTION"
  | "UNAUTHORIZED_AUTHORITY_INJECTION"
  | "UNAUTHORIZED_PROVIDER"
  | "LINEAGE_VIOLATION"
  | "DIGEST_MISMATCH";

export interface ParentValidationError {
  readonly code: ParentValidationErrorCode;
  readonly message: string;
  readonly field?: string | undefined;
  readonly details?: unknown | undefined;
}

export interface ValidatedWorkerPayload {
  readonly response: BinaryWorkerAnalyzeResponse;
  readonly decoderPayload?: DecoderPayload | undefined;
  readonly cfgPayload?: CfgPayload | undefined;
  readonly reachabilityPayload?: ReachabilityPayload | undefined;
  readonly taintPayload?: TaintPayload | undefined;
  readonly witnessPayload?: WitnessPayload | undefined;
  readonly candidates: readonly RawCandidate[];
}

export interface ValidatedEvidenceBundle {
  readonly decoderEvidence?:
    | TrustedAnalysisEvidence<DecoderPayload>
    | undefined;
  readonly cfgEvidence?: TrustedAnalysisEvidence<CfgPayload> | undefined;
  readonly reachabilityEvidence?:
    | TrustedAnalysisEvidence<ReachabilityPayload>
    | undefined;
  readonly taintEvidence?: TrustedAnalysisEvidence<TaintPayload> | undefined;
  readonly witnessEvidence?:
    | TrustedAnalysisEvidence<WitnessPayload>
    | undefined;
  readonly candidates: readonly RawCandidate[];
}

export interface AdjudicationPersistOptions {
  readonly storage: SqliteBlackboardStorage;
  readonly authority: TrustedEvidenceAuthority;
  readonly bridge: VulnerabilityAdjudicationBridge;
  readonly asset: BlackboardAssetRecord;
  readonly candidate: VulnerabilityCandidate;
  readonly bundle: ValidatedEvidenceBundle;
  readonly context: ParentValidationContext;
}

export interface AdjudicationPersistResult {
  readonly findingId: string;
  readonly state: FindingState;
  readonly evidenceIds: readonly string[];
  readonly outboxEventId: string;
}

// ============================================================================
// ParentEvidenceValidator Implementation
// ============================================================================

/**
 * Parent-Side Untrusted DTO Validator & Evidence Sealer.
 *
 * Implements Phase 3A Milestone 4:
 * 1. Independent Context Binding (C1): Verifies worker output matches parent-owned task state.
 * 2. Independent Input Integrity (C2): Computes SHA-256 of actual binary bytes, rejecting worker forgery.
 * 3. Strict DTO Semantic Validation (C3): Validates address bounds, graph edges, and rejects authority injection.
 * 4. Completeness Propagation (C4): Enforces that partial decodes cannot claim complete CFGs or unreachability.
 * 5. Parent Evidence Sealing: Seals validated payloads with TrustedEvidenceAuthority stage signers.
 * 6. Transactional Persistence: Persists finding state, outbox events, and evidence atomically in SQLite.
 */
export class ParentEvidenceValidator {
  /**
   * Validates an untrusted worker response against parent context and integrity rules.
   */
  public validateWorkerResponse(
    response: BinaryWorkerAnalyzeResponse,
    context: ParentValidationContext,
  ): Result<ValidatedWorkerPayload, ParentValidationError> {
    // ------------------------------------------------------------------------
    // C1: Context Binding
    // ------------------------------------------------------------------------
    if (response.protocolVersion !== BINARY_WORKER_PROTOCOL_VERSION) {
      return err({
        code: "SCHEMA_VIOLATION",
        message: `Protocol version mismatch: expected ${BINARY_WORKER_PROTOCOL_VERSION}, got ${response.protocolVersion}`,
        field: "protocolVersion",
      });
    }

    if (response.assessmentId !== context.assessmentId) {
      return err({
        code: "CONTEXT_MISMATCH",
        message: `Assessment mismatch: expected ${context.assessmentId}, got ${response.assessmentId}`,
        field: "assessmentId",
      });
    }

    if (response.assetId !== context.assetId) {
      return err({
        code: "CONTEXT_MISMATCH",
        message: `Asset mismatch: expected ${context.assetId}, got ${response.assetId}`,
        field: "assetId",
      });
    }

    if (
      response.binarySha256.toLowerCase() !== context.binarySha256.toLowerCase()
    ) {
      return err({
        code: "CONTEXT_MISMATCH",
        message: `Binary digest mismatch: expected ${context.binarySha256}, got ${response.binarySha256}`,
        field: "binarySha256",
      });
    }

    if (
      context.firmwareSha256 &&
      response.firmwareSha256 !== context.firmwareSha256
    ) {
      return err({
        code: "CONTEXT_MISMATCH",
        message: `Firmware digest mismatch: expected ${context.firmwareSha256}, got ${response.firmwareSha256 ?? "none"}`,
        field: "firmwareSha256",
      });
    }

    if (response.runId !== context.runId) {
      return err({
        code: "CONTEXT_MISMATCH",
        message: `Run mismatch: expected ${context.runId}, got ${response.runId}`,
        field: "runId",
      });
    }

    if (response.taskId !== context.taskId) {
      return err({
        code: "CONTEXT_MISMATCH",
        message: `Task mismatch: expected ${context.taskId}, got ${response.taskId}`,
        field: "taskId",
      });
    }

    if (response.fencingToken !== context.fencingToken) {
      return err({
        code: "CONTEXT_MISMATCH",
        message: `Fencing token mismatch: expected ${context.fencingToken}, got ${response.fencingToken}`,
        field: "fencingToken",
      });
    }

    if (response.workerId !== context.workerId) {
      return err({
        code: "CONTEXT_MISMATCH",
        message: `Worker ID mismatch: expected ${context.workerId}, got ${response.workerId}`,
        field: "workerId",
      });
    }

    if (
      context.requestedStage !== "ALL" &&
      response.stage !== context.requestedStage
    ) {
      return err({
        code: "CONTEXT_MISMATCH",
        message: `Stage mismatch: expected ${context.requestedStage}, got ${response.stage}`,
        field: "stage",
      });
    }

    // ------------------------------------------------------------------------
    // C2: Independent Input Integrity
    // ------------------------------------------------------------------------
    let inputBytes = context.binaryInputBytes;
    if (!inputBytes && context.binaryInputPath) {
      try {
        inputBytes = readFileSync(context.binaryInputPath);
      } catch (readErr: unknown) {
        return err({
          code: "INPUT_INTEGRITY_VIOLATION",
          message: `Parent failed to read binary input path '${context.binaryInputPath}': ${readErr instanceof Error ? readErr.message : String(readErr)}`,
        });
      }
    }

    if (inputBytes) {
      const computedSha256 = createHash("sha256")
        .update(inputBytes)
        .digest("hex");
      if (computedSha256.toLowerCase() !== context.binarySha256.toLowerCase()) {
        return err({
          code: "INPUT_INTEGRITY_VIOLATION",
          message: `Parent binary bytes digest ${computedSha256} does not match expected binary SHA-256 ${context.binarySha256}`,
        });
      }
      if (
        response.binarySha256.toLowerCase() !== computedSha256.toLowerCase()
      ) {
        return err({
          code: "INPUT_INTEGRITY_VIOLATION",
          message: `Worker reported binarySha256 ${response.binarySha256} does not match parent computed digest ${computedSha256}`,
        });
      }
    }

    // ------------------------------------------------------------------------
    // C3: DTO Structural Validation & Recomputed Digest Binding
    // ------------------------------------------------------------------------
    let computedPayloadDigest: string;
    try {
      computedPayloadDigest = canonicalDigest(response.resultPayload);
    } catch (cause) {
      return err({
        code: "SCHEMA_VIOLATION",
        message: `Failed to canonicalize worker resultPayload: ${cause instanceof Error ? cause.message : String(cause)}`,
      });
    }

    if (
      computedPayloadDigest.toLowerCase() !==
      response.resultDigest.toLowerCase()
    ) {
      return err({
        code: "DIGEST_MISMATCH",
        message: `Worker resultDigest tampered: declared ${response.resultDigest}, calculated ${computedPayloadDigest}`,
      });
    }

    const payload = response.resultPayload;

    // Check for unauthorized authority injection
    if (
      "signature" in (payload as any) ||
      "keyring" in (payload as any) ||
      "isAuthorized" in (payload as any) ||
      "evidenceId" in (payload as any)
    ) {
      return err({
        code: "UNAUTHORIZED_AUTHORITY_INJECTION",
        message:
          "Worker resultPayload contains disallowed authority fields or forged signatures",
      });
    }

    // Decoder payload validation
    let decoderPayload: DecoderPayload | undefined;
    if (payload.decoder) {
      const dec = payload.decoder;
      if (
        dec.totalBytes < 0 ||
        dec.decodedBytes < 0 ||
        dec.decodedBytes > dec.totalBytes
      ) {
        return err({
          code: "STRUCTURAL_INCONSISTENCY",
          message: `Invalid decoder byte counts: decoded ${dec.decodedBytes} of ${dec.totalBytes}`,
        });
      }

      const seenAddresses = new Set<number>();
      for (const inst of dec.instructions) {
        if (!Number.isSafeInteger(inst.address) || inst.address < 0) {
          return err({
            code: "STRUCTURAL_INCONSISTENCY",
            message: `Invalid instruction address: ${inst.address}`,
          });
        }
        if (inst.size <= 0 || inst.size > 64) {
          return err({
            code: "STRUCTURAL_INCONSISTENCY",
            message: `Invalid instruction size ${inst.size} at address ${inst.address}`,
          });
        }
        if (inst.rawBytesHex.length !== inst.size * 2) {
          return err({
            code: "STRUCTURAL_INCONSISTENCY",
            message: `Instruction rawBytesHex length ${inst.rawBytesHex.length} mismatch size ${inst.size} at address ${inst.address}`,
          });
        }
        if (seenAddresses.has(inst.address)) {
          return err({
            code: "STRUCTURAL_INCONSISTENCY",
            message: `Duplicate instruction address detected in decoder stream: 0x${inst.address.toString(16)}`,
          });
        }
        seenAddresses.add(inst.address);
      }

      const actualProvider = dec.provider ?? "InProcessInstructionDecoder";
      if (!AUTHORIZED_PROVIDERS.includes(actualProvider)) {
        return err({
          code: "UNAUTHORIZED_PROVIDER",
          message: `Worker emitted unauthorized decoder provider: '${actualProvider}'`,
        });
      }

      decoderPayload = {
        outcome: dec.outcome,
        architecture: dec.architecture,
        baseAddress: dec.baseAddress,
        totalBytes: dec.totalBytes,
        decodedBytes: dec.decodedBytes,
        instructions: dec.instructions as any,
        ...(dec.unhandledByteOffset !== undefined
          ? { unhandledByteOffset: dec.unhandledByteOffset }
          : {}),
        ...(dec.haltReason !== undefined ? { haltReason: dec.haltReason } : {}),
        provenance: {
          actualProvider,
          requestedProvider: actualProvider,
          isFallback: false,
          timestamp: Date.now(),
        },
      };
    }

    // CFG payload validation
    let cfgPayload: CfgPayload | undefined;
    if (payload.cfg) {
      const cfg = payload.cfg;
      const blockIds = new Set<string>();

      for (const block of cfg.blocks) {
        if (!block.id || block.id.trim().length === 0) {
          return err({
            code: "STRUCTURAL_INCONSISTENCY",
            message: "CFG basic block has empty ID",
          });
        }
        if (blockIds.has(block.id)) {
          return err({
            code: "STRUCTURAL_INCONSISTENCY",
            message: `Duplicate CFG block ID: '${block.id}'`,
          });
        }
        blockIds.add(block.id);

        if (block.startAddress > block.endAddress) {
          return err({
            code: "STRUCTURAL_INCONSISTENCY",
            message: `Invalid basic block address range: start ${block.startAddress} > end ${block.endAddress}`,
          });
        }
      }

      if (cfg.blocks.length > 0 && !blockIds.has(cfg.entryBlockId)) {
        return err({
          code: "STRUCTURAL_INCONSISTENCY",
          message: `CFG entryBlockId '${cfg.entryBlockId}' does not exist in basic blocks`,
        });
      }

      for (const edge of cfg.edges) {
        if (!blockIds.has(edge.sourceBlockId)) {
          return err({
            code: "STRUCTURAL_INCONSISTENCY",
            message: `CFG edge sourceBlockId '${edge.sourceBlockId}' does not exist in basic blocks`,
          });
        }
        if (!blockIds.has(edge.targetBlockId)) {
          return err({
            code: "STRUCTURAL_INCONSISTENCY",
            message: `CFG edge targetBlockId '${edge.targetBlockId}' does not exist in basic blocks`,
          });
        }
      }

      cfgPayload = {
        functionName: cfg.functionName,
        entryBlockId: cfg.entryBlockId,
        blocks: cfg.blocks as any,
        edges: cfg.edges as any,
        decodeOutcome: cfg.decodeOutcome,
        isComplete: cfg.isComplete,
        cfgHash: cfg.cfgHash,
        architecture: context.architecture,
      };
    }

    // Reachability payload validation
    let reachabilityPayload: ReachabilityPayload | undefined;
    if (payload.reachability) {
      const rch = payload.reachability;
      if (!rch.entryPoint || !rch.target) {
        return err({
          code: "STRUCTURAL_INCONSISTENCY",
          message: "Reachability missing entryPoint or target",
        });
      }

      // Check provider authorization
      const allowedProviders = context.allowedProviders ?? AUTHORIZED_PROVIDERS;
      if (rch.provider && !allowedProviders.includes(rch.provider)) {
        return err({
          code: "UNAUTHORIZED_PROVIDER",
          message: `Reachability provider '${rch.provider}' is not in authorized providers list`,
        });
      }

      reachabilityPayload = {
        status: rch.status,
        paths: rch.paths as any,
        entryPoint: rch.entryPoint,
        target: rch.target,
        deadCodeFunctions: rch.deadCodeFunctions,
        reasoning: rch.reasoning,
        provider: rch.provider,
        analysisOutcome: rch.analysisOutcome,
        isComplete: rch.isComplete,
      };
    }

    // Taint payload validation
    let taintPayload: TaintPayload | undefined;
    if (payload.taint) {
      const t = payload.taint;
      if (!t.sink || !t.sink.api) {
        return err({
          code: "STRUCTURAL_INCONSISTENCY",
          message: "Taint payload missing valid sink API",
        });
      }

      taintPayload = {
        status: t.status,
        ...(t.stageStatus !== undefined ? { stageStatus: t.stageStatus } : {}),
        ...(t.ruleId !== undefined ? { ruleId: t.ruleId } : {}),
        ...(t.category !== undefined ? { category: t.category } : {}),
        source: t.source as any,
        sink: t.sink as any,
        steps: t.steps as any,
        sanitizers: t.sanitizers as any,
        isSanitized: t.isSanitized,
        hasUnresolvedAliases: t.hasUnresolvedAliases,
        reasoning: t.reasoning,
      };
    }

    // Witness payload validation
    let witnessPayload: WitnessPayload | undefined;
    if (payload.witness) {
      const w = payload.witness;
      if (!w.witnessId || !w.ruleId || !w.category) {
        return err({
          code: "STRUCTURAL_INCONSISTENCY",
          message: "Witness payload missing witnessId, ruleId, or category",
        });
      }

      witnessPayload = {
        witnessId: w.witnessId,
        findingId: (w as any).findingId ?? `find_${w.ruleId}`,
        ruleId: w.ruleId,
        category: w.category,
        ...(w.sinkApi !== undefined ? { sinkApi: w.sinkApi } : {}),
        ...(w.stageStatus !== undefined ? { stageStatus: w.stageStatus } : {}),
        ...(w.satisfiabilityStatus !== undefined
          ? { satisfiabilityStatus: w.satisfiabilityStatus }
          : {}),
        isSatisfiable: w.isSatisfiable,
        isReproducible: w.isReproducible,
        exploitabilityStatus: w.exploitabilityStatus,
        conflictingGuards: w.conflictingGuards,
        validationLog: w.validationLog,
        constraints: w.constraints as any,
        verifiedAt: w.verifiedAt,
      };
    }

    // ------------------------------------------------------------------------
    // C4: Completeness Propagation Invariants
    // ------------------------------------------------------------------------
    const completeness = response.decodeCompleteness;
    if (completeness.outcome !== "SUCCESS") {
      if (completeness.isComplete) {
        return err({
          code: "COMPLETENESS_CONTRADICTION",
          message: `Contradiction: decode outcome '${completeness.outcome}' claimed isComplete = true`,
        });
      }

      if (cfgPayload && cfgPayload.isComplete) {
        return err({
          code: "COMPLETENESS_CONTRADICTION",
          message: `Contradiction: CFG claimed isComplete = true while parent decoder outcome is '${completeness.outcome}'`,
        });
      }

      if (reachabilityPayload && reachabilityPayload.status === "UNREACHABLE") {
        return err({
          code: "COMPLETENESS_CONTRADICTION",
          message:
            "Contradiction: Reachability claimed definitive UNREACHABLE on partial or failed decode",
        });
      }
    }

    // If CFG has unresolved indirect jumps or is incomplete, reachability cannot be UNREACHABLE
    if (reachabilityPayload && reachabilityPayload.status === "UNREACHABLE") {
      if (cfgPayload && !cfgPayload.isComplete) {
        return err({
          code: "COMPLETENESS_CONTRADICTION",
          message:
            "Contradiction: Reachability claimed UNREACHABLE on incomplete CFG",
        });
      }

      const hasIndirectJumps = reachabilityPayload.paths.some(
        (p) =>
          p.unresolvedIndirectJumps && p.unresolvedIndirectJumps.length > 0,
      );
      if (hasIndirectJumps) {
        return err({
          code: "COMPLETENESS_CONTRADICTION",
          message:
            "Contradiction: Reachability claimed UNREACHABLE with unresolved indirect jumps",
        });
      }
    }

    const validated: ValidatedWorkerPayload = {
      response,
      decoderPayload,
      cfgPayload,
      reachabilityPayload,
      taintPayload,
      witnessPayload,
      candidates: payload.candidates ?? [],
    };

    return ok(deepFreeze(validated));
  }

  // ==========================================================================
  // Stage D: Trusted Evidence Sealing
  // ==========================================================================

  /**
   * Seals validated worker payloads into cryptographically signed TrustedAnalysisEvidence
   * structures using the parent-owned TrustedEvidenceAuthority stage signers.
   */
  public sealValidatedEvidence(
    validated: ValidatedWorkerPayload,
    authority: TrustedEvidenceAuthority,
    context: ParentValidationContext,
  ): Result<ValidatedEvidenceBundle, EvidenceVerificationError> {
    const stageContext: StageContext = {
      assessmentId: context.assessmentId,
      assetId: context.assetId,
      binarySha256: context.binarySha256,
      firmwareSha256: context.firmwareSha256,
      runId: context.runId,
    };

    let decoderEvidence: TrustedAnalysisEvidence<DecoderPayload> | undefined;
    let cfgEvidence: TrustedAnalysisEvidence<CfgPayload> | undefined;
    let reachabilityEvidence:
      | TrustedAnalysisEvidence<ReachabilityPayload>
      | undefined;
    let taintEvidence: TrustedAnalysisEvidence<TaintPayload> | undefined;
    let witnessEvidence: TrustedAnalysisEvidence<WitnessPayload> | undefined;

    // 1. Seal Decoder Evidence
    if (validated.decoderPayload) {
      const decSigner = authority.createDecoderSigner(stageContext);
      const decRes = decSigner.signDecoderEvidence({
        payload: validated.decoderPayload,
        provider: validated.decoderPayload.provenance.actualProvider,
        architecture: context.architecture,
      });
      if (!decRes.ok) {
        return err(decRes.error);
      }
      decoderEvidence = decRes.value;
    }

    // 2. Seal CFG Evidence (Lineage: Requires Decoder Parent)
    if (validated.cfgPayload) {
      if (!decoderEvidence) {
        return err({
          code: "LINEAGE_INVALID",
          message:
            "Cannot seal CFG evidence: Missing required parent decoder evidence",
        });
      }

      const cfgSigner = authority.createCfgSigner(stageContext);
      const cfgRes = cfgSigner.signCfgEvidence({
        payload: validated.cfgPayload,
        parentDecoderEvidence: decoderEvidence,
        provider: "ReaControlFlowEngine",
      });
      if (!cfgRes.ok) {
        return err(cfgRes.error);
      }
      cfgEvidence = cfgRes.value;
    }

    // 3. Seal Reachability Evidence (Lineage: Requires CFG Parent)
    if (validated.reachabilityPayload) {
      if (!cfgEvidence) {
        return err({
          code: "LINEAGE_INVALID",
          message:
            "Cannot seal Reachability evidence: Missing required parent CFG evidence",
        });
      }

      const rchSigner = authority.createReachabilitySigner(stageContext);
      const rchRes = rchSigner.signReachabilityEvidence({
        payload: validated.reachabilityPayload,
        parentCfgEvidence: cfgEvidence,
        provider: "ReaControlFlowEngine",
      });
      if (!rchRes.ok) {
        return err(rchRes.error);
      }
      reachabilityEvidence = rchRes.value;
    }

    // 4. Seal Taint Evidence (Lineage: Requires CFG Parent)
    if (validated.taintPayload) {
      if (!cfgEvidence) {
        return err({
          code: "LINEAGE_INVALID",
          message:
            "Cannot seal Taint evidence: Missing required parent CFG evidence",
        });
      }

      const taintSigner = authority.createTaintSigner(stageContext);
      const taintRes = taintSigner.signTaintEvidence({
        payload: validated.taintPayload,
        parentCfgEvidence: cfgEvidence,
        provider: "ReaTaintEngine",
      });
      if (!taintRes.ok) {
        return err(taintRes.error);
      }
      taintEvidence = taintRes.value;
    }

    // 5. Seal Witness Evidence (Lineage: Requires Taint Parent)
    if (validated.witnessPayload) {
      if (!taintEvidence) {
        return err({
          code: "LINEAGE_INVALID",
          message:
            "Cannot seal Witness evidence: Missing required parent Taint evidence",
        });
      }

      const witnessSigner = authority.createWitnessSigner(stageContext);
      const witnessRes = witnessSigner.signWitnessEvidence({
        payload: validated.witnessPayload,
        parentTaintEvidence: taintEvidence,
        provider: "ReaWitnessEngine",
      });
      if (!witnessRes.ok) {
        return err(witnessRes.error);
      }
      witnessEvidence = witnessRes.value;
    }

    return ok({
      decoderEvidence,
      cfgEvidence,
      reachabilityEvidence,
      taintEvidence,
      witnessEvidence,
      candidates: validated.candidates,
    });
  }

  // ==========================================================================
  // Stage E & F: Adjudication & Atomic Transactional Persistence
  // ==========================================================================

  /**
   * Adjudicates a candidate finding using sealed evidence and transactionally persists
   * finding state, witness consumption, and outbox event into the SQLite blackboard.
   */
  public adjudicateAndPersist(
    options: AdjudicationPersistOptions,
  ): Result<AdjudicatedFindingResult, { code: string; message: string }> {
    const { storage, authority, bridge, asset, candidate, bundle, context } =
      options;

    // Execute everything inside an atomic SQLite transaction
    return storage.transaction((tx) => {
      // 1. Verify Task Ownership & Fencing Token
      const taskRow = tx.db
        .prepare("SELECT fencing_token, status FROM tasks WHERE id = ?")
        .get(context.taskId) as any;

      if (!taskRow) {
        throw new Error(
          `TASK_NOT_FOUND: Task ${context.taskId} does not exist in blackboard`,
        );
      }
      if (taskRow.fencing_token !== context.fencingToken) {
        throw new Error(
          `STALE_TASK_LEASE: Task ${context.taskId} fencing token mismatch: expected ${taskRow.fencing_token}, received ${context.fencingToken}`,
        );
      }

      // 2. Verify Run Freshness
      const runManager = authority.getRunManager();
      const run = runManager.getRun(context.runId);
      if (!run) {
        throw new Error(
          `RUN_VERIFICATION_FAILED: Run ${context.runId} not found`,
        );
      }
      if (run.status !== "ACTIVE") {
        throw new Error(
          `RUN_VERIFICATION_FAILED: Run ${context.runId} status is ${run.status} (RUN_${run.status})`,
        );
      }
      if (run.assessmentId !== context.assessmentId) {
        throw new Error(
          `RUN_VERIFICATION_FAILED: Run assessmentId ${run.assessmentId} does not match context ${context.assessmentId}`,
        );
      }
      if (run.assetId !== context.assetId) {
        throw new Error(
          `RUN_VERIFICATION_FAILED: Run assetId ${run.assetId} does not match context ${context.assetId}`,
        );
      }
      if (
        run.binarySha256.toLowerCase() !== context.binarySha256.toLowerCase()
      ) {
        throw new Error(
          `RUN_VERIFICATION_FAILED: Run binarySha256 ${run.binarySha256} does not match context ${context.binarySha256}`,
        );
      }

      // 3. Consume Single-Use Witness Evidence if present and matches candidate
      const isWitnessMatchingCandidate =
        bundle.witnessEvidence !== undefined &&
        bundle.witnessEvidence.payload.ruleId === candidate.ruleId &&
        bundle.witnessEvidence.payload.category === candidate.category;

      if (bundle.witnessEvidence && isWitnessMatchingCandidate) {
        const witnessEvidenceId = bundle.witnessEvidence.claims.evidenceId;
        if (runManager.isEvidenceConsumed(witnessEvidenceId)) {
          throw new Error(
            `WITNESS_REPLAY_DETECTED: Evidence ${witnessEvidenceId} has already been consumed (REPLAY_DETECTED)`,
          );
        }
      }

      // 4. Adjudicate candidate with bridge
      const adjudicateRes = bridge.adjudicateCandidate(
        context.assessmentId,
        asset,
        candidate,
        {
          trustedReachability: bundle.reachabilityEvidence,
          trustedTaint: bundle.taintEvidence,
          trustedWitness: bundle.witnessEvidence,
          runId: context.runId,
          firmwareSha256: context.firmwareSha256,
        },
      );

      if (!adjudicateRes.ok) {
        throw new Error(`ADJUDICATION_FAILED: ${String(adjudicateRes)}`);
      }

      const adjudicated = adjudicateRes.value;

      // 5. Persist Finding Record Transition
      const now = Date.now();
      const existingFinding = tx.db
        .prepare("SELECT id, cas_version FROM findings WHERE id = ?")
        .get(adjudicated.finding.id) as any;

      const findingState = adjudicated.lifecycleState as FindingState;
      const cweList = adjudicated.finding.classification?.cwe ?? [];

      if (existingFinding) {
        tx.db
          .prepare(
            `UPDATE findings
             SET state = ?, severity_json = ?, confidence_json = ?, evidence_ids_json = ?, cas_version = cas_version + 1, updated_at = ?
             WHERE id = ? AND cas_version = ?`,
          )
          .run(
            findingState,
            JSON.stringify(adjudicated.finding.severity),
            JSON.stringify(adjudicated.finding.confidence),
            JSON.stringify(adjudicated.finding.evidence_ids),
            now,
            existingFinding.id,
            existingFinding.cas_version,
          );
      } else {
        tx.db
          .prepare(
            `INSERT INTO findings (
              id, assessment_id, fingerprint, asset_id, title, description, state,
              cwe_json, severity_json, confidence_json, location_json, evidence_ids_json,
              remediation_json, cas_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
          )
          .run(
            adjudicated.finding.id,
            context.assessmentId,
            adjudicated.finding.id,
            context.assetId,
            adjudicated.finding.name,
            adjudicated.finding.technical_description,
            findingState,
            JSON.stringify(cweList),
            JSON.stringify(adjudicated.finding.severity),
            JSON.stringify(adjudicated.finding.confidence),
            JSON.stringify(adjudicated.finding.location),
            JSON.stringify(adjudicated.finding.evidence_ids),
            adjudicated.finding.remediation
              ? JSON.stringify(adjudicated.finding.remediation)
              : null,
            now,
            now,
          );
      }

      // 6. Queue Outbox Event
      const outboxPayload = {
        findingId: adjudicated.finding.id,
        assessmentId: context.assessmentId,
        assetId: context.assetId,
        candidateRuleId: candidate.ruleId,
        finalState: findingState,
        evidenceIds: adjudicated.finding.evidence_ids,
        runId: context.runId,
        taskId: context.taskId,
      };

      tx.queueOutbox(
        "finding_adjudicated",
        "finding",
        adjudicated.finding.id,
        context.assessmentId,
        outboxPayload,
      );

      // 7. Update Task Status to completed with Fencing Check
      tx.db
        .prepare(
          `UPDATE tasks
           SET status = 'completed', result_json = ?, cas_version = cas_version + 1, updated_at = ?
           WHERE id = ? AND fencing_token = ?`,
        )
        .run(
          JSON.stringify({
            findingId: adjudicated.finding.id,
            state: findingState,
            evidenceIds: adjudicated.finding.evidence_ids,
          }),
          now,
          context.taskId,
          context.fencingToken,
        );

      return ok(adjudicated);
    });
  }
}
