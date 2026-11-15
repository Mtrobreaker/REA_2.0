import { isAbsolute, normalize, relative, resolve } from "node:path";
import { z } from "zod";
import { digestSchema, SHA256_PATTERN } from "../../../domain/digests.js";
import { err, ok, type Result } from "../../../domain/result.js";

// ============================================================================
// Protocol Version & Byte Limits Constants
// ============================================================================

export const BINARY_WORKER_PROTOCOL_VERSION = "1.0.0" as const;

/** Maximum byte budget for IPC control frames (handshake, heartbeat, cancel, shutdown, errors). */
export const BINARY_IPC_CONTROL_FRAME_MAX_BYTES = 64 * 1024; // 64 KiB

/** Maximum byte budget for IPC analysis data frames (request & response with payload graphs). */
export const BINARY_IPC_DATA_FRAME_MAX_BYTES = 16 * 1024 * 1024; // 16 MiB

/** Maximum buffer length kept in memory before rejecting un-delimited streams. */
export const BINARY_IPC_MAX_PENDING_BYTES =
  BINARY_IPC_DATA_FRAME_MAX_BYTES + 1024;

/** Hard ceiling on file input size for local analysis tasks. */
export const BINARY_INPUT_MAX_FILE_BYTES = 512 * 1024 * 1024; // 512 MiB

/** Hard ceiling on inline buffer size for firmware components. */
export const BINARY_INPUT_MAX_INLINE_BYTES = 16 * 1024 * 1024; // 16 MiB

// ============================================================================
// Core Primitive Validations
// ============================================================================

export const idPatternSchema = (prefix: string, maxLen = 128) =>
  z
    .string()
    .min(1)
    .max(maxLen)
    .regex(
      new RegExp(`^${prefix}_[a-zA-Z0-9_-]+$`),
      `Expected identifier with prefix '${prefix}_'`,
    );

export const uuidSchema = z
  .string()
  .uuid("Expected valid RFC 4122 UUIDv4 identifier");

export const positiveFiniteInt = z.number().finite().int().positive();
export const nonNegativeFiniteInt = z.number().finite().int().nonnegative();
export const finiteFloat01 = z.number().finite().min(0).max(1);

export const supportedArchEnum = z.enum([
  "x86_64",
  "ARM",
  "ARM32",
  "Thumb",
  "MIPS_BE",
  "MIPS_LE",
]);

export const analysisStageEnum = z.enum([
  "PARSE",
  "DECODE",
  "CFG",
  "REACHABILITY",
  "TAINT",
  "WITNESS",
  "ALL",
]);

export const vulnerabilityCategoryEnum = z.enum([
  "unsafe_memory_operations",
  "command_injection",
  "path_traversal",
  "authentication_weakness",
  "cryptographic_weakness",
  "network_exposure",
  "hardcoded_secrets",
  "firmware_configuration",
]);

export const stageEvaluationStatusEnum = z.enum([
  "NOT_ATTEMPTED",
  "UNSUPPORTED",
  "INCONCLUSIVE",
  "SATISFIABLE",
  "UNSATISFIABLE",
  "PROVEN",
]);

// ============================================================================
// Binary Input Reference Schema (Section 5)
// ============================================================================

export const binaryInputReferenceSchema = z.discriminatedUnion("type", [
  // Type 1: File path reference within controlled sandbox root
  z.strictObject({
    type: z.literal("file_path"),
    path: z.string().min(1).max(1024),
    expected_sha256: digestSchema,
    byte_size: positiveFiniteInt.max(BINARY_INPUT_MAX_FILE_BYTES),
    read_only: z.literal(true),
  }),
  // Type 2: In-memory buffer reference (bounded to 16 MiB, max ~22 MiB base64)
  z.strictObject({
    type: z.literal("inline_buffer"),
    expected_sha256: digestSchema,
    byte_size: positiveFiniteInt.max(BINARY_INPUT_MAX_INLINE_BYTES),
    data_base64: z
      .string()
      .min(1)
      .max(23 * 1024 * 1024),
    read_only: z.literal(true),
  }),
]);

export type BinaryInputReference = z.infer<typeof binaryInputReferenceSchema>;

/**
 * Validates that a file-based binary input reference is strictly safe:
 * - Must be an absolute path
 * - Must not contain directory traversal elements ('..')
 * - Must reside strictly within the designated allowed root directory (if provided)
 */
export function validateBinaryInputReference(
  ref: BinaryInputReference,
  allowedRoot?: string,
): Result<
  void,
  { code: "PATH_TRAVERSAL_DETECTED" | "INVALID_PATH"; message: string }
> {
  if (ref.type === "inline_buffer") {
    return ok(undefined);
  }

  const rawPath = ref.path;
  if (!isAbsolute(rawPath)) {
    return err({
      code: "INVALID_PATH",
      message: `Binary input path must be an absolute path, got: '${rawPath}'`,
    });
  }

  const normalized = normalize(rawPath);
  if (rawPath.includes("..") || normalized.includes("..")) {
    return err({
      code: "PATH_TRAVERSAL_DETECTED",
      message: `Binary input path contains directory traversal sequences: '${rawPath}'`,
    });
  }

  if (allowedRoot) {
    const rootNormalized = resolve(normalize(allowedRoot));
    const targetNormalized = resolve(normalized);
    const rel = relative(rootNormalized, targetNormalized);
    if (rel.startsWith("..") || isAbsolute(rel)) {
      return err({
        code: "PATH_TRAVERSAL_DETECTED",
        message: `Binary input path '${targetNormalized}' escapes allowed root directory '${rootNormalized}'`,
      });
    }
  }

  return ok(undefined);
}

// ============================================================================
// Raw Worker Payload Schemas (Untrusted Analysis DTOs)
// ============================================================================

export const rawInstructionSchema = z.strictObject({
  address: nonNegativeFiniteInt,
  mnemonic: z.string().min(1).max(32),
  operands: z.string().max(256),
  size: positiveFiniteInt.max(64),
  rawBytesHex: z
    .string()
    .regex(/^[0-9a-fA-F]*$/)
    .max(128),
  isBranch: z.boolean(),
  isConditional: z.boolean(),
  isCall: z.boolean(),
  isReturn: z.boolean(),
  isIndirect: z.boolean(),
  targetAddress: nonNegativeFiniteInt.nullable(),
});

export const rawDecoderCompletenessSchema = z.strictObject({
  isComplete: z.boolean(),
  outcome: z.enum(["SUCCESS", "PARTIAL", "FAILED"]),
  decodedBytes: nonNegativeFiniteInt,
  totalBytes: nonNegativeFiniteInt,
  unhandledByteOffset: nonNegativeFiniteInt.optional(),
  haltReason: z.string().max(256).optional(),
});

export const rawCandidateSchema = z.strictObject({
  ruleId: z.string().min(1).max(128),
  category: vulnerabilityCategoryEnum,
  name: z.string().min(1).max(256),
  functionName: z.string().min(1).max(256),
  sinkApi: z.string().min(1).max(128),
  functionAddress: z.string().max(32).nullable(),
  callAddress: z.string().max(32).nullable(),
  callerInfo: z.string().max(256).nullable(),
  detectionMethod: z.string().max(64),
  confidenceScore: finiteFloat01,
  technicalDescription: z.string().max(4096),
  cwe: z.array(z.string().max(32)).max(10),
});

export const rawDecoderPayloadSchema = z.strictObject({
  outcome: z.enum(["SUCCESS", "PARTIAL", "FAILED"]),
  architecture: z.string().max(32),
  baseAddress: nonNegativeFiniteInt,
  totalBytes: nonNegativeFiniteInt,
  decodedBytes: nonNegativeFiniteInt,
  instructions: z.array(rawInstructionSchema).max(100_000),
  provider: z.string().max(64).optional(),
  unhandledByteOffset: nonNegativeFiniteInt.optional(),
  haltReason: z.string().max(256).optional(),
});

export const rawBasicBlockSchema = z.strictObject({
  id: z.string().min(1).max(64),
  startAddress: nonNegativeFiniteInt,
  endAddress: nonNegativeFiniteInt,
  functionName: z.string().min(1).max(256),
  instructionsCount: nonNegativeFiniteInt,
  predecessorIds: z.array(z.string().max(64)).max(1_000),
  successorIds: z.array(z.string().max(64)).max(1_000),
  terminatorType: z.enum([
    "branch",
    "conditional_branch",
    "call",
    "return",
    "halt",
    "fallthrough",
  ]),
});

export const rawControlFlowEdgeSchema = z.strictObject({
  sourceBlockId: z.string().min(1).max(64),
  targetBlockId: z.string().min(1).max(64),
  edgeType: z.enum([
    "conditional_true",
    "conditional_false",
    "unconditional",
    "fallthrough",
    "indirect",
  ]),
});

export const rawCfgPayloadSchema = z.strictObject({
  functionName: z.string().min(1).max(256),
  entryBlockId: z.string().min(1).max(64),
  blocks: z.array(rawBasicBlockSchema).max(10_000),
  edges: z.array(rawControlFlowEdgeSchema).max(50_000),
  decodeOutcome: z.string().max(32),
  isComplete: z.boolean(),
  cfgHash: z.string().max(64),
});

export const rawReachabilityPathSchema = z.strictObject({
  source: z.string().min(1).max(256),
  target: z.string().min(1).max(256),
  steps: z
    .array(
      z.strictObject({
        functionName: z.string().max(256),
        blockId: z.string().max(64),
        address: nonNegativeFiniteInt,
        description: z.string().max(256),
      }),
    )
    .max(500),
  isDefinitive: z.boolean(),
  unresolvedIndirectJumps: z.array(nonNegativeFiniteInt).max(100),
});

export const rawReachabilityPayloadSchema = z.strictObject({
  status: z.enum(["REACHABLE", "UNREACHABLE", "INCONCLUSIVE"]),
  paths: z.array(rawReachabilityPathSchema).max(1_000),
  entryPoint: z.string().min(1).max(256),
  target: z.string().min(1).max(256),
  deadCodeFunctions: z.array(z.string().max(256)).max(5_000),
  reasoning: z.string().max(4096),
  provider: z.string().max(64),
  analysisOutcome: z.string().max(32),
  isComplete: z.boolean(),
});

export const rawTaintSourceSchema = z.strictObject({
  kind: z.enum([
    "network_socket",
    "environment_variable",
    "command_line",
    "file_read",
    "ipc_pipe",
  ]),
  api: z.string().min(1).max(128),
  functionName: z.string().min(1).max(256),
  address: nonNegativeFiniteInt,
  targetParameterOrReturn: z.number().finite().int().min(-1).max(16),
});

export const rawTaintSinkSchema = z.strictObject({
  api: z.string().min(1).max(128),
  functionName: z.string().min(1).max(256),
  address: nonNegativeFiniteInt,
  vulnerableParameterIndex: z.number().finite().int().nonnegative().max(16),
});

export const rawTaintStepSchema = z.strictObject({
  functionName: z.string().max(256),
  address: nonNegativeFiniteInt,
  operation: z.enum([
    "parameter_pass",
    "register_copy",
    "arithmetic",
    "pointer_dereference",
    "call_return",
  ]),
  variableOrRegister: z.string().max(64),
  description: z.string().max(256),
});

export const rawSanitizerGuardSchema = z.strictObject({
  functionName: z.string().max(256),
  address: nonNegativeFiniteInt,
  type: z.enum([
    "bounds_check",
    "whitelist_validation",
    "null_check",
    "length_check",
  ]),
  expression: z.string().max(512),
  isSound: z.boolean(),
  dominatesSink: z.boolean(),
});

export const rawTaintPayloadSchema = z.strictObject({
  status: z.enum([
    "PROVEN_TAINT",
    "NO_TAINT",
    "MITIGATED_TAINT",
    "INCONCLUSIVE",
    "NOT_ATTEMPTED",
    "UNSUPPORTED",
  ]),
  stageStatus: stageEvaluationStatusEnum.optional(),
  ruleId: z.string().min(1).max(128).optional(),
  category: z.string().min(1).max(64).optional(),
  source: rawTaintSourceSchema.nullable(),
  sink: rawTaintSinkSchema,
  steps: z.array(rawTaintStepSchema).max(10_000),
  sanitizers: z.array(rawSanitizerGuardSchema).max(1_000),
  isSanitized: z.boolean(),
  hasUnresolvedAliases: z.boolean(),
  reasoning: z.string().max(4096),
});

export const rawWitnessConstraintSchema = z.strictObject({
  parameter: z.string().max(64),
  type: z.enum([
    "length_bound",
    "character_set",
    "null_termination",
    "format_specifier",
    "numeric_range",
  ]),
  expectedValue: z.string().max(512),
  description: z.string().max(512),
});

export const rawWitnessPayloadSchema = z.strictObject({
  witnessId: z.string().min(1).max(128),
  findingId: z.string().min(1).max(128),
  ruleId: z.string().min(1).max(128),
  category: z.string().min(1).max(64),
  sinkApi: z.string().min(1).max(128).optional(),
  stageStatus: stageEvaluationStatusEnum.optional(),
  satisfiabilityStatus: stageEvaluationStatusEnum.optional(),
  isSatisfiable: z.boolean(),
  isReproducible: z.boolean(),
  exploitabilityStatus: z.enum([
    "PROVEN",
    "THEORETICAL",
    "UNSATISFIABLE",
    "NOT_ATTEMPTED",
    "UNSUPPORTED",
    "INCONCLUSIVE",
  ]),
  conflictingGuards: z.array(z.string().max(512)).max(100),
  validationLog: z.array(z.string().max(1024)).max(1_000),
  constraints: z.array(rawWitnessConstraintSchema).max(1_000),
  verifiedAt: z.string().max(64),
});

export const rawAnalysisResultPayloadSchema = z.strictObject({
  metadata: z
    .strictObject({
      sha256: digestSchema,
      architecture: z.string().max(32),
      endianness: z.enum(["little", "big"]),
      elfClass: z.enum(["32", "64"]),
      entryPoint: z.string().max(32),
      isExecutable: z.boolean(),
      sectionsCount: nonNegativeFiniteInt,
      programHeadersCount: nonNegativeFiniteInt,
      dynamicLibraries: z.array(z.string().max(256)).max(1_000),
    })
    .optional(),
  candidates: z.array(rawCandidateSchema).max(10_000).optional(),
  decoder: rawDecoderPayloadSchema.optional(),
  cfg: rawCfgPayloadSchema.optional(),
  reachability: rawReachabilityPayloadSchema.optional(),
  taint: rawTaintPayloadSchema.optional(),
  witness: rawWitnessPayloadSchema.optional(),
});

export type RawInstruction = z.infer<typeof rawInstructionSchema>;
export type RawDecoderCompleteness = z.infer<
  typeof rawDecoderCompletenessSchema
>;
export type RawCandidate = z.infer<typeof rawCandidateSchema>;
export type RawDecoderPayload = z.infer<typeof rawDecoderPayloadSchema>;
export type RawBasicBlock = z.infer<typeof rawBasicBlockSchema>;
export type RawControlFlowEdge = z.infer<typeof rawControlFlowEdgeSchema>;
export type RawCfgPayload = z.infer<typeof rawCfgPayloadSchema>;
export type RawReachabilityPath = z.infer<typeof rawReachabilityPathSchema>;
export type RawReachabilityPayload = z.infer<
  typeof rawReachabilityPayloadSchema
>;
export type RawTaintSource = z.infer<typeof rawTaintSourceSchema>;
export type RawTaintSink = z.infer<typeof rawTaintSinkSchema>;
export type RawTaintStep = z.infer<typeof rawTaintStepSchema>;
export type RawSanitizerGuard = z.infer<typeof rawSanitizerGuardSchema>;
export type RawTaintPayload = z.infer<typeof rawTaintPayloadSchema>;
export type RawWitnessConstraint = z.infer<typeof rawWitnessConstraintSchema>;
export type RawWitnessPayload = z.infer<typeof rawWitnessPayloadSchema>;
export type RawAnalysisResultPayload = z.infer<
  typeof rawAnalysisResultPayloadSchema
>;

// ============================================================================
// 1. BinaryWorkerRequest Schema (Parent -> Worker)
// ============================================================================

export const binaryWorkerAnalyzeRequestSchema = z.strictObject({
  protocolVersion: z.literal(BINARY_WORKER_PROTOCOL_VERSION),
  kind: z.literal("ANALYZE_REQUEST"),
  messageId: uuidSchema,
  taskId: idPatternSchema("tsk"),
  assessmentId: idPatternSchema("asm"),
  assetId: idPatternSchema("ast"),
  firmwareSha256: digestSchema.optional(),
  binarySha256: digestSchema,
  runId: idPatternSchema("run"),
  fencingToken: positiveFiniteInt,
  workerId: idPatternSchema("wkr"),
  requestedStage: analysisStageEnum,
  binaryInput: binaryInputReferenceSchema,
  analysisConfiguration: z.strictObject({
    architecture: supportedArchEnum,
    entryPoints: z.array(z.string().min(1).max(256)).max(100).default(["main"]),
    targetFunctions: z.array(z.string().min(1).max(256)).max(1_000).optional(),
    targetSinkApi: z.string().min(1).max(128).optional(),
    candidateRuleId: z.string().min(1).max(128).optional(),
    candidateCategory: z.string().min(1).max(64).optional(),
    maxInstructions: positiveFiniteInt.max(500_000).default(100_000),
    maxCfgBlocks: positiveFiniteInt.max(50_000).default(10_000),
    maxPaths: positiveFiniteInt.max(2_000).default(500),
  }),
  deadline: positiveFiniteInt,
});

export type BinaryWorkerAnalyzeRequest = z.infer<
  typeof binaryWorkerAnalyzeRequestSchema
>;

// ============================================================================
// 2. BinaryWorkerResponse Schema (Worker -> Parent, Untrusted)
// ============================================================================

export const binaryWorkerAnalyzeResponseSchema = z.strictObject({
  protocolVersion: z.literal(BINARY_WORKER_PROTOCOL_VERSION),
  kind: z.literal("ANALYZE_RESPONSE"),
  messageId: uuidSchema,
  inReplyTo: uuidSchema,
  taskId: idPatternSchema("tsk"),
  assessmentId: idPatternSchema("asm"),
  assetId: idPatternSchema("ast"),
  firmwareSha256: digestSchema.optional(),
  binarySha256: digestSchema,
  runId: idPatternSchema("run"),
  fencingToken: positiveFiniteInt,
  workerId: idPatternSchema("wkr"),
  stage: analysisStageEnum,
  executionStatus: z.enum(["SUCCESS", "PARTIAL", "FAILED"]),
  decodeCompleteness: rawDecoderCompletenessSchema,
  resultPayload: rawAnalysisResultPayloadSchema,
  resultDigest: digestSchema,
  diagnostics: z.array(z.string().max(512)).max(100).default([]),
  resourceUsage: z.strictObject({
    cpuTimeMs: nonNegativeFiniteInt,
    peakMemoryBytes: nonNegativeFiniteInt,
    wallTimeMs: nonNegativeFiniteInt,
  }),
});

export type BinaryWorkerAnalyzeResponse = z.infer<
  typeof binaryWorkerAnalyzeResponseSchema
>;

// ============================================================================
// 3. Lifecycle & Control Messages
// ============================================================================

export const binaryWorkerReadySchema = z.strictObject({
  protocolVersion: z.literal(BINARY_WORKER_PROTOCOL_VERSION),
  kind: z.literal("WORKER_READY"),
  messageId: uuidSchema,
  workerId: idPatternSchema("wkr"),
  pid: positiveFiniteInt,
  supportedArchitectures: z.array(supportedArchEnum).min(1).max(10),
  heapLimitBytes: positiveFiniteInt.nullable(),
});

export const binaryWorkerHeartbeatSchema = z.strictObject({
  protocolVersion: z.literal(BINARY_WORKER_PROTOCOL_VERSION),
  kind: z.literal("HEARTBEAT"),
  messageId: uuidSchema,
  workerId: idPatternSchema("wkr"),
  timestamp: positiveFiniteInt,
  activeTaskId: idPatternSchema("tsk").nullable(),
  fencingToken: positiveFiniteInt.nullable(),
});

export const binaryWorkerCancelRequestSchema = z.strictObject({
  protocolVersion: z.literal(BINARY_WORKER_PROTOCOL_VERSION),
  kind: z.literal("CANCEL"),
  messageId: uuidSchema,
  taskId: idPatternSchema("tsk"),
  reason: z.string().min(1).max(256),
});

export const binaryWorkerCancelAckResponseSchema = z.strictObject({
  protocolVersion: z.literal(BINARY_WORKER_PROTOCOL_VERSION),
  kind: z.literal("CANCEL_ACK"),
  messageId: uuidSchema,
  inReplyTo: uuidSchema,
  taskId: idPatternSchema("tsk"),
  status: z.enum(["CANCELLED", "TASK_ALREADY_COMPLETED", "TASK_NOT_FOUND"]),
});

export const binaryWorkerShutdownRequestSchema = z.strictObject({
  protocolVersion: z.literal(BINARY_WORKER_PROTOCOL_VERSION),
  kind: z.literal("SHUTDOWN"),
  messageId: uuidSchema,
  reason: z.string().min(1).max(256),
  gracePeriodMs: nonNegativeFiniteInt.max(10_000).default(1_000),
});

export const binaryWorkerShutdownAckResponseSchema = z.strictObject({
  protocolVersion: z.literal(BINARY_WORKER_PROTOCOL_VERSION),
  kind: z.literal("SHUTDOWN_ACK"),
  messageId: uuidSchema,
  inReplyTo: uuidSchema,
  workerId: idPatternSchema("wkr"),
});

export const binaryWorkerErrorResponseSchema = z.strictObject({
  protocolVersion: z.literal(BINARY_WORKER_PROTOCOL_VERSION),
  kind: z.literal("WORKER_ERROR"),
  messageId: uuidSchema,
  inReplyTo: uuidSchema.optional(),
  taskId: idPatternSchema("tsk").optional(),
  code: z.enum([
    "MALFORMED_REQUEST",
    "RESOURCE_EXHAUSTED",
    "INTERNAL_ERROR",
    "TIMEOUT",
    "CRASH",
  ]),
  message: z.string().min(1).max(1024),
  recoverable: z.boolean(),
});

export type BinaryWorkerReady = z.infer<typeof binaryWorkerReadySchema>;
export type BinaryWorkerHeartbeat = z.infer<typeof binaryWorkerHeartbeatSchema>;
export type BinaryWorkerCancelRequest = z.infer<
  typeof binaryWorkerCancelRequestSchema
>;
export type BinaryWorkerCancelAckResponse = z.infer<
  typeof binaryWorkerCancelAckResponseSchema
>;
export type BinaryWorkerShutdownRequest = z.infer<
  typeof binaryWorkerShutdownRequestSchema
>;
export type BinaryWorkerShutdownAckResponse = z.infer<
  typeof binaryWorkerShutdownAckResponseSchema
>;
export type BinaryWorkerErrorResponse = z.infer<
  typeof binaryWorkerErrorResponseSchema
>;

// ============================================================================
// Discriminated Union of All Messages
// ============================================================================

export const binaryWorkerIpcMessageSchema = z.discriminatedUnion("kind", [
  binaryWorkerAnalyzeRequestSchema,
  binaryWorkerAnalyzeResponseSchema,
  binaryWorkerReadySchema,
  binaryWorkerHeartbeatSchema,
  binaryWorkerCancelRequestSchema,
  binaryWorkerCancelAckResponseSchema,
  binaryWorkerShutdownRequestSchema,
  binaryWorkerShutdownAckResponseSchema,
  binaryWorkerErrorResponseSchema,
]);

export type BinaryWorkerIpcMessage = z.infer<
  typeof binaryWorkerIpcMessageSchema
>;

export const binaryWorkerParentMessageSchema = z.discriminatedUnion("kind", [
  binaryWorkerAnalyzeRequestSchema,
  binaryWorkerCancelRequestSchema,
  binaryWorkerShutdownRequestSchema,
]);

export type BinaryWorkerParentMessage = z.infer<
  typeof binaryWorkerParentMessageSchema
>;

export const binaryWorkerChildMessageSchema = z.discriminatedUnion("kind", [
  binaryWorkerReadySchema,
  binaryWorkerHeartbeatSchema,
  binaryWorkerAnalyzeResponseSchema,
  binaryWorkerCancelAckResponseSchema,
  binaryWorkerShutdownAckResponseSchema,
  binaryWorkerErrorResponseSchema,
]);

export type BinaryWorkerChildMessage = z.infer<
  typeof binaryWorkerChildMessageSchema
>;

// ============================================================================
// Parent-Side Context Validation Helper
// ============================================================================

export interface ExpectedTaskContext {
  readonly assessmentId: string;
  readonly assetId: string;
  readonly binarySha256: string;
  readonly firmwareSha256?: string | undefined;
  readonly runId: string;
  readonly taskId: string;
  readonly fencingToken: number;
  readonly workerId: string;
}

export interface ContextMismatchError {
  readonly code:
    | "ASSESSMENT_MISMATCH"
    | "ASSET_MISMATCH"
    | "BINARY_MISMATCH"
    | "RUN_MISMATCH"
    | "TASK_MISMATCH"
    | "FENCING_TOKEN_MISMATCH"
    | "WORKER_MISMATCH";
  readonly message: string;
}

/**
 * Validates that an untrusted worker response matches the active parent task execution context.
 */
export function validateResponseContext(
  expected: ExpectedTaskContext,
  actual: BinaryWorkerAnalyzeResponse,
): Result<void, ContextMismatchError> {
  if (actual.assessmentId !== expected.assessmentId) {
    return err({
      code: "ASSESSMENT_MISMATCH",
      message: `Cross-assessment response rejected: expected ${expected.assessmentId}, got ${actual.assessmentId}`,
    });
  }
  if (actual.assetId !== expected.assetId) {
    return err({
      code: "ASSET_MISMATCH",
      message: `Cross-asset response rejected: expected ${expected.assetId}, got ${actual.assetId}`,
    });
  }
  if (actual.binarySha256 !== expected.binarySha256) {
    return err({
      code: "BINARY_MISMATCH",
      message: `Binary digest mismatch: expected ${expected.binarySha256}, got ${actual.binarySha256}`,
    });
  }
  if (actual.runId !== expected.runId) {
    return err({
      code: "RUN_MISMATCH",
      message: `Cross-run response rejected: expected run ${expected.runId}, got ${actual.runId}`,
    });
  }
  if (actual.taskId !== expected.taskId) {
    return err({
      code: "TASK_MISMATCH",
      message: `Task ID mismatch: expected ${expected.taskId}, got ${actual.taskId}`,
    });
  }
  if (actual.fencingToken !== expected.fencingToken) {
    return err({
      code: "FENCING_TOKEN_MISMATCH",
      message: `Stale fencing token rejected: expected ${expected.fencingToken}, got ${actual.fencingToken}`,
    });
  }
  if (actual.workerId !== expected.workerId) {
    return err({
      code: "WORKER_MISMATCH",
      message: `Worker identity mismatch: expected ${expected.workerId}, got ${actual.workerId}`,
    });
  }
  return ok(undefined);
}
