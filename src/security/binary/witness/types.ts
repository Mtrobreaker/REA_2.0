/**
 * Witness Generation & Exploitability Verification Types.
 */

export type ConstraintType =
  | "min_length"
  | "max_length"
  | "character_present"
  | "character_absent"
  | "format_specifier"
  | "magic_value";

export interface InputConstraint {
  readonly parameter: string;
  readonly type: ConstraintType;
  readonly expectedValue: string | number | readonly string[];
  readonly description: string;
}

export interface ExecutionEnvironment {
  readonly architecture: string;
  readonly endianness: "little" | "big";
  readonly os: "linux" | "baremetal";
  readonly mode: "simulated_harness" | "isolated_sandbox";
  readonly configuration: Readonly<Record<string, unknown>>;
  readonly runtimeVersion: string;
}

export interface WitnessArtifact {
  readonly witnessId: string;
  readonly findingId: string;
  readonly ruleId: string;
  readonly category: string;
  readonly source: {
    readonly api: string;
    readonly address: number;
    readonly functionName: string;
  };
  readonly sink: {
    readonly api: string;
    readonly address: number;
    readonly functionName: string;
  };
  readonly executionPathAddresses: readonly number[];
  readonly constraints: readonly InputConstraint[];
  readonly preconditions: readonly string[];
  readonly reproductionPayloadDescription: string;
  readonly environment: ExecutionEnvironment;
  readonly artifactDigest: string;
  readonly generatedAt: string;
}

export interface WitnessValidationResult {
  readonly witnessId: string;
  readonly isSatisfiable: boolean;
  readonly isReproducible: boolean;
  readonly exploitabilityStatus: "PROVEN" | "THEORETICAL" | "UNSATISFIABLE";
  readonly evaluatedPreconditionsCount: number;
  readonly conflictingGuards: readonly string[];
  readonly validationLog: readonly string[];
  readonly verifiedAt: string;
}

