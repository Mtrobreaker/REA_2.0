/**
 * Types and Contracts for Interprocedural Taint Analysis.
 */

export type TaintSourceKind =
  | "network_socket"
  | "environment_variable"
  | "config_file"
  | "command_line"
  | "request_parameter";

export interface TaintSource {
  readonly kind: TaintSourceKind;
  readonly api: string;
  readonly functionName: string;
  readonly address: number;
  readonly targetParameterOrReturn: "return" | number;
  readonly variableName?: string;
}

export interface TaintSink {
  readonly api: string;
  readonly functionName: string;
  readonly address: number;
  readonly vulnerableParameterIndex: number; // 0-indexed
}

export type SanitizerType =
  | "bounds_check"
  | "character_whitelist"
  | "escaping"
  | "length_truncation"
  | "equality_check";

export interface SanitizerGuard {
  readonly functionName: string;
  readonly address: number;
  readonly type: SanitizerType;
  readonly expression: string;
  readonly isSound: boolean;
  readonly dominatesSink: boolean;
}

export interface TaintPathStep {
  readonly functionName: string;
  readonly address: number;
  readonly operation:
    | "source_introduction"
    | "parameter_pass"
    | "register_transfer"
    | "sanitization_attempt"
    | "sink_consumption";
  readonly variableOrRegister: string;
  readonly description: string;
}

export type TaintStatus =
  | "PROVEN_TAINT"
  | "MITIGATED_TAINT"
  | "NO_TAINT"
  | "INCONCLUSIVE";

export interface TaintFlowResult {
  readonly status: TaintStatus;
  readonly source: TaintSource | null;
  readonly sink: TaintSink;
  readonly steps: readonly TaintPathStep[];
  readonly sanitizers: readonly SanitizerGuard[];
  readonly isSanitized: boolean;
  readonly hasUnresolvedAliases: boolean;
  readonly evidenceId: string;
  readonly reasoning: string;
}

