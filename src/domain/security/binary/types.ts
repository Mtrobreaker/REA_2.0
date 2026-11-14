import type { AssetId } from "../asset.js";
import type { SecurityFinding } from "../finding.js";
import type { VulnerabilityLifecycleState } from "../classification.js";

export type { SecurityFinding };

export type ElfClass = "ELF32" | "ELF64";
export type Endianness = "little" | "big";

export interface ElfSectionHeader {
  readonly name: string;
  readonly type: number;
  readonly typeName: string;
  readonly flags: number;
  readonly address: string;
  readonly offset: number;
  readonly size: number;
}

export interface ElfProgramHeader {
  readonly type: number;
  readonly typeName: string;
  readonly flags: number;
  readonly offset: number;
  readonly vaddr: string;
  readonly paddr: string;
  readonly filesz: number;
  readonly memsz: number;
}

export interface BinarySymbol {
  readonly name: string;
  readonly type: "FUNC" | "OBJECT" | "NOTYPE" | "SECTION" | "FILE" | "UNKNOWN";
  readonly binding: "GLOBAL" | "LOCAL" | "WEAK" | "UNKNOWN";
  readonly address: string | null;
  readonly size: number;
  readonly sectionIndex?: number | undefined;
}

export interface DiscoveredString {
  readonly offset: number;
  readonly value: string;
  readonly section?: string | undefined;
}

export interface DiscoveredFunction {
  readonly name: string;
  readonly address: string;
  readonly size: number;
  readonly isExported: boolean;
  readonly calls: readonly string[];
  readonly stringReferences: readonly string[];
  readonly securitySensitiveCalls: readonly string[];
  readonly pseudocode?: string | undefined;
}

export interface CallRelationship {
  readonly caller: string;
  readonly callee: string;
  readonly address?: string | undefined;
}

export interface SecuritySensitiveApiCall {
  readonly caller: string;
  readonly api: string;
  readonly address?: string | undefined;
  readonly category: VulnerabilityCategory;
}

export interface BinaryAnalysisMetadata {
  readonly sha256: string;
  readonly elfClass: ElfClass;
  readonly endianness: Endianness;
  readonly architecture: string;
  readonly entryPoint: string;
  readonly sections: readonly ElfSectionHeader[];
  readonly programHeaders: readonly ElfProgramHeader[];
  readonly dynamicLibraries: readonly string[];
  readonly importedSymbols: readonly BinarySymbol[];
  readonly exportedSymbols: readonly BinarySymbol[];
  readonly strings: readonly DiscoveredString[];
  readonly isExecutable: boolean;
}

export interface BinaryAnalysisReport {
  readonly metadata: BinaryAnalysisMetadata;
  readonly functions: readonly DiscoveredFunction[];
  readonly callRelationships: readonly CallRelationship[];
  readonly securitySensitiveCalls: readonly SecuritySensitiveApiCall[];
  readonly decompiledFunctions: Readonly<Record<string, string>>;
  readonly provenance: {
    readonly provider: string;
    readonly version: string;
    readonly executionMode: "in-process" | "supervised-process";
    readonly timestamp: number;
  };
}

export type VulnerabilityCategory =
  | "unsafe_memory_operations"
  | "command_injection"
  | "path_traversal"
  | "authentication_weakness"
  | "cryptographic_weakness"
  | "network_exposure"
  | "firmware_configuration";

export type DetectionMethod =
  | "L1_LEXICAL"
  | "L2_HEURISTIC"
  | "L3_REACHABILITY"
  | "L4_TAINT"
  | "L5_WITNESS";

export interface VulnerabilityCandidate {
  readonly binaryAssetId: AssetId;
  readonly ruleId: string;
  readonly category: VulnerabilityCategory;
  readonly name: string;
  readonly functionName: string;
  readonly functionAddress: string | null;
  readonly sinkApi: string;
  readonly callAddress: string | null;
  readonly callerInfo: string | null;
  readonly sourceOfInput: string | null;
  readonly guardInfo: {
    readonly claimedGuard?: string;
    readonly isSound?: boolean;
    readonly reason?: string;
  } | null;
  readonly evidenceReferences: readonly string[];
  readonly detectionMethod: DetectionMethod;
  readonly confidenceScore: number;
  readonly confidenceLimitations: readonly string[];
  readonly cwe: readonly string[];
  readonly technicalDescription: string;
  readonly remediationGuidance: string;
}

export interface AdjudicatedFindingResult {
  readonly finding: SecurityFinding;
  readonly lifecycleState: VulnerabilityLifecycleState;
  readonly evidenceId: string;
  readonly reasoning: string;
}

export interface BinaryAnalysisError {
  readonly code:
    | "FILE_READ_ERROR"
    | "INVALID_BINARY"
    | "PARSER_FAILURE"
    | "PROVIDER_UNAVAILABLE"
    | "EXECUTION_TIMEOUT"
    | "TASK_ERROR";
  readonly message: string;
  readonly cause?: unknown;
}
