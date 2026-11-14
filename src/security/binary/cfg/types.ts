import type { Result } from "../../../domain/result.js";

/**
 * Control-Flow Graph (CFG) and Instruction-level Reachability Types.
 */

export type Architecture = "ARM" | "MIPS" | "x86_64" | "unknown";

export type DecodeOutcome = "SUCCESS" | "PARTIAL" | "MALFORMED" | "UNSUPPORTED" | "FAILED";

export interface DecodeProvenance {
  readonly actualProvider: string;
  readonly requestedProvider?: string;
  readonly isFallback: boolean;
  readonly fallbackReason?: string;
  readonly timestamp: number;
}

export interface Instruction {
  readonly address: number;
  readonly mnemonic: string;
  readonly operands: string;
  readonly size: number;
  readonly rawBytes: Uint8Array;
  readonly isBranch: boolean;
  readonly isConditional: boolean;
  readonly isCall: boolean;
  readonly isReturn: boolean;
  readonly isIndirect: boolean;
  readonly targetAddress: number | null;
  readonly hasDelaySlot?: boolean | undefined;
  readonly isMalformed?: boolean | undefined;
  readonly prefixes?: readonly string[] | undefined;
  readonly isaMode?: "MIPS32" | "MIPS16" | "ARM" | "Thumb" | "x86_64" | undefined;
}

export class InstructionDecodeError extends Error {
  public readonly architecture: Architecture;
  public readonly address: number;
  public readonly rawBytes: Uint8Array;
  public readonly outcome: DecodeOutcome;

  constructor(
    message: string,
    architecture: Architecture,
    address: number,
    rawBytes: Uint8Array,
    outcome: DecodeOutcome = "FAILED",
  ) {
    super(message);
    this.name = "InstructionDecodeError";
    this.architecture = architecture;
    this.address = address;
    this.rawBytes = rawBytes;
    this.outcome = outcome;
  }
}

export interface DecodeOptions {
  readonly architecture: Architecture;
  readonly isLittleEndian?: boolean | undefined;
  readonly isThumb?: boolean | undefined;
  readonly isMips16?: boolean | undefined;
  readonly mips16Regions?: readonly { readonly start: number; readonly end: number }[] | undefined;
  readonly preferredProvider?: string | undefined;
}

export interface DecodeResult extends ReadonlyArray<Instruction> {
  readonly outcome: DecodeOutcome;
  readonly instructions: readonly Instruction[];
  readonly architecture: Architecture;
  readonly baseAddress: number;
  readonly totalBytes: number;
  readonly decodedBytes: number;
  readonly provenance: DecodeProvenance;
  readonly error?: InstructionDecodeError;
  readonly haltReason?: string;
  readonly unhandledByteOffset?: number;
}

export interface InstructionDecoderProvider {
  readonly name: string;
  readonly supportedArchitectures: readonly Architecture[];
  canDecode(options: DecodeOptions): boolean;
  decode(
    bytes: Uint8Array,
    baseAddress: number,
    options: DecodeOptions,
  ): Result<DecodeResult, InstructionDecodeError>;
}

export type BlockTerminator =
  | "fallthrough"
  | "branch"
  | "conditional_branch"
  | "call"
  | "return"
  | "indirect"
  | "halt";

export interface BasicBlock {
  readonly id: string;
  readonly startAddress: number;
  readonly endAddress: number;
  readonly functionName: string;
  readonly instructions: readonly Instruction[];
  readonly predecessorIds: readonly string[];
  readonly successorIds: readonly string[];
  readonly terminatorType: BlockTerminator;
}

export type EdgeType =
  | "fallthrough"
  | "jump"
  | "true_branch"
  | "false_branch"
  | "call"
  | "return";

export interface ControlFlowEdge {
  readonly fromBlockId: string;
  readonly toBlockId: string;
  readonly type: EdgeType;
  readonly condition?: string | undefined;
}

export interface ControlFlowGraph {
  readonly functionName: string;
  readonly entryBlockId: string;
  readonly blocks: ReadonlyMap<string, BasicBlock>;
  readonly edges: readonly ControlFlowEdge[];
  readonly architecture: Architecture;
  readonly decodeOutcome?: DecodeOutcome | undefined;
  readonly isComplete?: boolean | undefined;
  readonly decodeError?: string | undefined;
  readonly provenance?: DecodeProvenance | undefined;
}

export interface FunctionCallEdge {
  readonly callerFunction: string;
  readonly callerAddress: number;
  readonly calleeFunction: string;
  readonly calleeAddress: number | null;
  readonly isIndirect: boolean;
}

export interface InterproceduralCallGraph {
  readonly functions: readonly string[];
  readonly edges: readonly FunctionCallEdge[];
  readonly entryPoints: readonly string[];
}

export interface ReachabilityStep {
  readonly functionName: string;
  readonly blockId: string;
  readonly address: number;
  readonly description: string;
}

export interface ReachabilityPath {
  readonly source: string;
  readonly target: string;
  readonly steps: readonly ReachabilityStep[];
  readonly isDefinitive: boolean;
  readonly unresolvedIndirectJumps: readonly number[];
}

export interface ReachabilityAnalysisResult {
  readonly status: "REACHABLE" | "UNREACHABLE" | "INCONCLUSIVE";
  readonly paths: readonly ReachabilityPath[];
  readonly entryPoint: string;
  readonly target: string;
  readonly deadCodeFunctions: readonly string[];
  readonly reasoning: string;
  readonly provider: string;
  readonly provenance?: DecodeProvenance | undefined;
  readonly analysisOutcome?: DecodeOutcome | undefined;
  readonly isComplete?: boolean | undefined;
}

export type FunctionBoundaryStatus = "VERIFIED" | "INFERRED" | "OPEN";

export type FunctionEntrySource =
  | "ELF_ENTRY"
  | "DT_INIT"
  | "DT_FINI"
  | "INIT_ARRAY"
  | "FINI_ARRAY"
  | "EXPORT_SYMBOL"
  | "LOCAL_SYMBOL"
  | "PLT_STUB"
  | "DIRECT_CALL_TARGET"
  | "PROLOGUE_SIGNATURE"
  | "CONTROL_FLOW_INFERENCE";

export interface RecoveredFunction {
  readonly name: string;
  readonly entryAddress: number;
  readonly endAddress: number;
  readonly size: number;
  readonly isaMode: "MIPS32" | "MIPS16" | "ARM" | "Thumb" | "x86_64";
  readonly entrySource: FunctionEntrySource;
  readonly boundaryStatus: FunctionBoundaryStatus;
  readonly instructionCount: number;
  readonly basicBlockCount: number;
  readonly directCalls: readonly number[];
  readonly indirectCalls: readonly number[];
  readonly returns: readonly number[];
  readonly tailCalls: readonly number[];
  readonly hasDelaySlots: boolean;
}

export interface FunctionRecoveryResult {
  readonly functions: readonly RecoveredFunction[];
  readonly totalRecovered: number;
  readonly verifiedBoundariesCount: number;
  readonly inferredBoundariesCount: number;
  readonly mips16FunctionsCount: number;
  readonly mips32FunctionsCount: number;
}


