export interface StaleFencingTokenError {
  readonly code: "STALE_FENCING_TOKEN";
  readonly taskId: string;
  readonly expectedToken: number;
  readonly submittedToken: number;
  readonly message: string;
}

export interface TaskBlockedError {
  readonly code: "TASK_BLOCKED";
  readonly taskId: string;
  readonly unresolvedDependencies: readonly string[];
  readonly message: string;
}

export interface TaskNotFoundError {
  readonly code: "TASK_NOT_FOUND";
  readonly taskId: string;
  readonly message: string;
}

export interface AssetNotFoundError {
  readonly code: "ASSET_NOT_FOUND";
  readonly assetId: string;
  readonly message: string;
}

export interface AssessmentNotFoundError {
  readonly code: "ASSESSMENT_NOT_FOUND";
  readonly assessmentId: string;
  readonly message: string;
}

export interface FindingNotFoundError {
  readonly code: "FINDING_NOT_FOUND";
  readonly findingId: string;
  readonly message: string;
}

export interface ObservationNotFoundError {
  readonly code: "OBSERVATION_NOT_FOUND";
  readonly observationId: string;
  readonly message: string;
}

export interface EvidenceNotFoundError {
  readonly code: "EVIDENCE_NOT_FOUND";
  readonly evidenceId: string;
  readonly message: string;
}

export interface CasConflictError {
  readonly code: "CAS_CONFLICT";
  readonly entityId: string;
  readonly expectedVersion: number;
  readonly actualVersion: number;
  readonly currentEntity: unknown;
  readonly message: string;
}

export interface AssessmentIsolationError {
  readonly code: "ASSESSMENT_ISOLATION_VIOLATION";
  readonly expectedAssessmentId: string;
  readonly actualAssessmentId: string;
  readonly entityId: string;
  readonly message: string;
}

export interface LeaseRenewalExceededError {
  readonly code: "LEASE_RENEWAL_EXCEEDED";
  readonly taskId: string;
  readonly renewals: number;
  readonly maxRenewals: number;
  readonly message: string;
}

export interface MaxConcurrencyExceededError {
  readonly code: "MAX_CONCURRENCY_EXCEEDED";
  readonly maxConcurrency: number;
  readonly currentWorkers: number;
  readonly message: string;
}

export interface TaskExecutionTimeoutError {
  readonly code: "TASK_TIMEOUT";
  readonly taskId: string;
  readonly timeoutMs: number;
  readonly message: string;
}

export interface BlackboardStorageError {
  readonly code: "STORAGE_ERROR";
  readonly operation: string;
  readonly message: string;
  readonly cause?: unknown;
}

export type BlackboardError =
  | StaleFencingTokenError
  | TaskBlockedError
  | TaskNotFoundError
  | AssetNotFoundError
  | AssessmentNotFoundError
  | FindingNotFoundError
  | ObservationNotFoundError
  | EvidenceNotFoundError
  | CasConflictError
  | AssessmentIsolationError
  | LeaseRenewalExceededError
  | MaxConcurrencyExceededError
  | TaskExecutionTimeoutError
  | BlackboardStorageError;

