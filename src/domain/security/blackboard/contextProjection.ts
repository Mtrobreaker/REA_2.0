import type { Result } from "../../result.js";
import type { AssessmentId } from "../assessment.js";
import type { AssetId } from "../asset.js";
import type { AssetRecord, ObservationRecord } from "./types.js";
import type { BlackboardError } from "./errors.js";

export interface ContextBudgetConfig {
  readonly default_byte_budget: number;
  readonly max_byte_budget: number;
}

export const DEFAULT_CONTEXT_BUDGET_CONFIG: ContextBudgetConfig = {
  default_byte_budget: 4096,
  max_byte_budget: 16384,
};

export interface TargetAssetMetadata {
  readonly asset_id: string;
  readonly name: string;
  readonly path?: string | undefined;
  readonly file_type: string;
  readonly sha256?: string | undefined;
  readonly architecture?: string | undefined;
  readonly endianness?: "little" | "big" | undefined;
}

export interface ParentFirmwareMetadata {
  readonly root_name: string;
  readonly os_flavor?: string | undefined;
}

export interface ProjectedObservation {
  readonly key: string;
  readonly value: unknown;
  readonly confidence: number;
  readonly source_tool: string;
  readonly evidence_id: string | null;
  readonly is_conflict?: boolean | undefined;
}

export interface ContextMetrics {
  readonly total_available_observations: number;
  readonly included_observations: number;
  readonly omitted_observations: number;
  readonly serialized_bytes: number;
  readonly estimated_tokens: number;
  readonly truncated: boolean;
}

export interface TaskContextProjection {
  // Mandatory Metadata (Never Omitted)
  readonly task_id: string;
  readonly task_type: string;
  readonly fencing_token: number;
  readonly assessment_id: string;
  readonly target_asset: TargetAssetMetadata;
  readonly parent_firmware: ParentFirmwareMetadata;
  // Bounded & Prioritized Observations
  readonly relevant_observations: ReadonlyArray<ProjectedObservation>;
  // Explicit Truncation Accounting
  readonly context_metrics: ContextMetrics;
}

export interface ProjectContextOptions {
  readonly byteBudget?: number | undefined;
}

export interface EvidenceRecord {
  readonly evidence_id: string;
  readonly assessment_id: string;
  readonly sha256: string;
  readonly content_type: string;
  readonly payload: unknown;
  readonly created_at: number;
}

export interface IContextProjector {
  projectTaskContext(
    assessmentId: AssessmentId,
    taskId: string,
    options?: ProjectContextOptions,
  ): Promise<Result<TaskContextProjection, BlackboardError>>;

  getAsset(
    assessmentId: AssessmentId,
    assetId: AssetId,
  ): Promise<Result<AssetRecord, BlackboardError>>;

  getObservation(
    assessmentId: AssessmentId,
    observationId: string,
  ): Promise<Result<ObservationRecord, BlackboardError>>;

  getEvidenceRecord(
    assessmentId: AssessmentId,
    evidenceId: string,
  ): Promise<Result<EvidenceRecord, BlackboardError>>;
}

