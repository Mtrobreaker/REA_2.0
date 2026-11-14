import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { AssetId } from "../../../domain/security/asset.js";

export interface AnalysisStageRecord {
  readonly stage: string;
  readonly provider: string;
  readonly version: string;
  readonly timestamp: number;
  readonly details: Readonly<Record<string, unknown>>;
}

export interface EvidenceArtifactRecord {
  readonly name: string;
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
}

export interface SealedInvestigationManifest {
  readonly assessmentId: AssessmentId;
  readonly totalAuditEntries: number;
  readonly genesisHash: string;
  readonly finalEntryHash: string;
  readonly binariesEvaluated: ReadonlyArray<{
    readonly name: string;
    readonly sha256: string;
  }>;
  readonly findingsAdjudicated: ReadonlyArray<{
    readonly findingId: string;
    readonly finalState: string;
    readonly witnessDigest?: string | undefined;
  }>;
  readonly artifacts: ReadonlyArray<EvidenceArtifactRecord>;
  readonly manifestDigest: string;
  readonly manifestHmacSignature: string;
  readonly sealedAt: string;
}

export interface SealingError {
  readonly code: "INTEGRITY_COMPROMISED" | "VERIFICATION_FAILED" | "STORAGE_ERROR";
  readonly message: string;
  readonly details?: unknown;
}

// ============================================================================
// Sprint 3B: Trusted Analysis Evidence Types & Contracts
// ============================================================================

export type AnalysisStage = "DECODER" | "CFG" | "REACHABILITY" | "TAINT" | "WITNESS";

export interface DecoderCompletenessClaim {
  readonly isComplete: boolean;
  readonly outcome: string;
  readonly decodedBytes: number;
  readonly totalBytes: number;
  readonly unhandledByteOffset?: number | undefined;
}

export interface TrustedEvidenceClaims {
  readonly evidenceId: string;
  readonly schemaVersion: "1.0.0";
  readonly stage: AnalysisStage;
  readonly assessmentId: AssessmentId;
  readonly assetId: AssetId;
  readonly firmwareSha256: string;
  readonly binarySha256: string;
  readonly runId: string;
  readonly provider: string;
  readonly providerImplementation: string;
  readonly providerVersion: string;
  readonly providerBuild: string;
  readonly decoderConfig: Readonly<Record<string, unknown>>;
  readonly architecture: string;
  readonly executionMode: string;
  readonly cfgHash: string;
  readonly decodeCompleteness: DecoderCompletenessClaim;
  readonly parentEvidenceIds: readonly string[];
  readonly timestamp: number;
  readonly canonicalizationVersion: "RFC8785_JCS_V1";
  readonly hashAlgorithm: "SHA256";
  readonly payloadDigest: string;
}

export interface TrustedAnalysisEvidence<TPayload = unknown> {
  readonly claims: TrustedEvidenceClaims;
  readonly payload: TPayload;
  readonly claimsDigest: string;
  readonly signature: string;
  readonly keyVersion: number;
}

// Stage-specific Canonical Payloads (serializable, deep-frozen DTOs)

export interface CanonicalInstruction {
  readonly address: number;
  readonly mnemonic: string;
  readonly operands: string;
  readonly size: number;
  readonly rawBytesHex: string;
  readonly isBranch: boolean;
  readonly isConditional: boolean;
  readonly isCall: boolean;
  readonly isReturn: boolean;
  readonly isIndirect: boolean;
  readonly targetAddress: number | null;
}

export interface DecoderPayload {
  readonly instructions: readonly CanonicalInstruction[];
  readonly outcome: string;
  readonly architecture: string;
  readonly baseAddress: number;
  readonly totalBytes: number;
  readonly decodedBytes: number;
  readonly unhandledByteOffset?: number | undefined;
  readonly haltReason?: string | undefined;
  readonly provenance: {
    readonly actualProvider: string;
    readonly requestedProvider?: string | undefined;
    readonly isFallback: boolean;
    readonly fallbackReason?: string | undefined;
    readonly timestamp: number;
  };
}

export interface CanonicalBasicBlock {
  readonly id: string;
  readonly startAddress: number;
  readonly endAddress: number;
  readonly functionName: string;
  readonly instructionsCount: number;
  readonly predecessorIds: readonly string[];
  readonly successorIds: readonly string[];
  readonly terminatorType: string;
}

export interface CanonicalControlFlowEdge {
  readonly fromBlockId: string;
  readonly toBlockId: string;
  readonly type: string;
  readonly condition?: string | undefined;
}

export interface CanonicalFunctionCallEdge {
  readonly callerFunction: string;
  readonly callerAddress: number;
  readonly calleeFunction: string;
  readonly calleeAddress: number | null;
  readonly isIndirect: boolean;
}

export interface CfgPayload {
  readonly functionName: string;
  readonly entryBlockId: string;
  readonly blocks: readonly CanonicalBasicBlock[];
  readonly edges: readonly CanonicalControlFlowEdge[];
  readonly callEdges?: readonly CanonicalFunctionCallEdge[] | undefined;
  readonly architecture: string;
  readonly decodeOutcome: string;
  readonly isComplete: boolean;
  readonly decodeError?: string | undefined;
  readonly cfgHash: string;
}

export interface CanonicalReachabilityStep {
  readonly functionName: string;
  readonly blockId: string;
  readonly address: number;
  readonly description: string;
}

export interface CanonicalReachabilityPath {
  readonly source: string;
  readonly target: string;
  readonly steps: readonly CanonicalReachabilityStep[];
  readonly isDefinitive: boolean;
  readonly unresolvedIndirectJumps: readonly number[];
}

export interface ReachabilityPayload {
  readonly status: "REACHABLE" | "UNREACHABLE" | "INCONCLUSIVE";
  readonly paths: readonly CanonicalReachabilityPath[];
  readonly entryPoint: string;
  readonly target: string;
  readonly deadCodeFunctions: readonly string[];
  readonly reasoning: string;
  readonly provider: string;
  readonly analysisOutcome: string;
  readonly isComplete: boolean;
}

export interface CanonicalTaintStep {
  readonly functionName: string;
  readonly address: number;
  readonly operation: string;
  readonly variableOrRegister: string;
  readonly description: string;
}

export interface CanonicalSanitizerGuard {
  readonly functionName: string;
  readonly address: number;
  readonly type: string;
  readonly expression: string;
  readonly isSound: boolean;
  readonly dominatesSink: boolean;
}

export interface TaintPayload {
  readonly status: "PROVEN_TAINT" | "NO_TAINT" | "MITIGATED_TAINT" | "INCONCLUSIVE";
  readonly source: {
    readonly kind: string;
    readonly api: string;
    readonly functionName: string;
    readonly address: number;
    readonly targetParameterOrReturn?: number | "return" | undefined;
  } | null;
  readonly sink: {
    readonly api: string;
    readonly functionName: string;
    readonly address: number;
    readonly vulnerableParameterIndex: number;
  };
  readonly steps: readonly CanonicalTaintStep[];
  readonly sanitizers: readonly CanonicalSanitizerGuard[];
  readonly isSanitized: boolean;
  readonly hasUnresolvedAliases: boolean;
  readonly reasoning: string;
}

export interface CanonicalWitnessConstraint {
  readonly parameter: string;
  readonly type: string;
  readonly expectedValue: unknown;
  readonly description: string;
}

export interface WitnessPayload {
  readonly witnessId: string;
  readonly findingId: string;
  readonly ruleId: string;
  readonly category: string;
  readonly isSatisfiable: boolean;
  readonly isReproducible: boolean;
  readonly exploitabilityStatus: "PROVEN" | "THEORETICAL" | "UNSATISFIABLE";
  readonly conflictingGuards: readonly string[];
  readonly validationLog: readonly string[];
  readonly constraints: readonly CanonicalWitnessConstraint[];
  readonly verifiedAt: string;
}

export type EvidenceVerificationErrorCode =
  | "INVALID_SCHEMA_VERSION"
  | "INVALID_PAYLOAD_DIGEST"
  | "INVALID_CLAIMS_DIGEST"
  | "SIGNATURE_INVALID"
  | "KEY_UNAVAILABLE"
  | "KEY_REVOKED"
  | "STAGE_MISMATCH"
  | "LINEAGE_INVALID"
  | "PARENT_NOT_FOUND"
  | "CROSS_ASSESSMENT_REUSE"
  | "CROSS_ASSET_REUSE"
  | "CROSS_BINARY_REUSE"
  | "CROSS_RUN_REUSE"
  | "RUN_INACTIVE"
  | "RUN_REVOKED"
  | "RUN_COMPLETED"
  | "REPLAY_DETECTED"
  | "UNAUTHORIZED_PROVIDER"
  | "INCOMPLETE_DECODE"
  | "MUTATION_DETECTED"
  | "CANONICALIZATION_ERROR";

export interface EvidenceVerificationError {
  readonly code: EvidenceVerificationErrorCode;
  readonly message: string;
  readonly details?: unknown;
}

export type AnalysisRunStatus = "ACTIVE" | "COMPLETED" | "REVOKED";

export interface AnalysisRunRecord {
  readonly runId: string;
  readonly assessmentId: AssessmentId;
  readonly assetId: AssetId;
  readonly binarySha256: string;
  readonly status: AnalysisRunStatus;
  readonly nonce: string;
  readonly createdAt: number;
  readonly completedAt?: number | undefined;
}
