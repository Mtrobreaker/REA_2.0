/**
 * Benchmark and Conformance Testing Types.
 */

export type GroundTruthClass =
  | "VULNERABLE"
  | "FIXED_MITIGATED"
  | "FALSE_POSITIVE"
  | "INCONCLUSIVE";

export interface BenchmarkSample {
  readonly id: string;
  readonly name: string;
  readonly architecture: "ARM" | "MIPS" | "x86_64";
  readonly category: string;
  readonly groundTruth: GroundTruthClass;
  readonly description: string;
  readonly binaryBuffer: Buffer;
  readonly expectedCandidate: boolean;
  readonly expectedVerified: boolean;
}

export interface BenchmarkConfusionMatrix {
  readonly truePositives: number;
  readonly falsePositives: number;
  readonly trueNegatives: number;
  readonly falseNegatives: number;
  readonly precision: number;
  readonly recall: number;
  readonly f1Score: number;
  readonly accuracy: number;
}

export interface SampleEvaluationResult {
  readonly sampleId: string;
  readonly sampleName: string;
  readonly groundTruth: GroundTruthClass;
  readonly candidateDetected: boolean;
  readonly proofVerified: boolean;
  readonly adjudicatedState: string;
  readonly evidenceId: string | null;
  readonly executionTimeMs: number;
}

export interface BenchmarkReport {
  readonly totalSamples: number;
  readonly candidateMetrics: BenchmarkConfusionMatrix;
  readonly proofVerificationMetrics: BenchmarkConfusionMatrix;
  readonly verificationCoverage: number;
  readonly reproducibleEvidencePercentage: number;
  readonly evaluations: readonly SampleEvaluationResult[];
  readonly timestamp: string;
}

