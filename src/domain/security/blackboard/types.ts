import type { Result } from "../../result.js";
import type { AssessmentId, AssessmentObjective, AssessmentMetrics, AuthorizationScope } from "../assessment.js";
import type { AssetId, AssetType, AssetEnvironment } from "../asset.js";
import type { FindingId, FindingLocation, FindingSeverity, FindingConfidence, FindingRemediation } from "../finding.js";
import type { BlackboardError } from "./errors.js";

// ==========================================
// 1. Assessment Models & Repository
// ==========================================

export type AssessmentStatus =
  | "initialization"
  | "active"
  | "reconnaissance"
  | "vulnerability_discovery"
  | "verification"
  | "remediation"
  | "completed"
  | "failed";

export interface AssessmentRecord {
  readonly id: AssessmentId;
  readonly name: string;
  readonly status: AssessmentStatus;
  readonly objective: AssessmentObjective;
  readonly authorization: AuthorizationScope;
  readonly metrics: AssessmentMetrics;
  readonly created_at: number;
  readonly updated_at: number;
}

export interface IAssessmentRepository {
  create(assessment: AssessmentRecord): Promise<Result<AssessmentRecord, BlackboardError>>;
  findById(id: AssessmentId): Promise<Result<AssessmentRecord | null, BlackboardError>>;
  updateStatus(
    id: AssessmentId,
    status: AssessmentStatus,
    metrics?: Partial<AssessmentMetrics>,
  ): Promise<Result<AssessmentRecord, BlackboardError>>;
  list(): Promise<Result<ReadonlyArray<AssessmentRecord>, BlackboardError>>;
}

// ==========================================
// 2. Asset Models & Repository
// ==========================================

export interface BlackboardAssetRecord {
  readonly id: AssetId;
  readonly assessment_id: AssessmentId;
  readonly parent_asset_id: AssetId | null;
  readonly name: string;
  readonly type: AssetType;
  readonly path: string | null;
  readonly digest: { readonly sha256: string } | null;
  readonly architecture: string | null;
  readonly version: string | null;
  readonly environment: AssetEnvironment | null;
  readonly tags: readonly string[];
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly created_at: number;
}

export type AssetRecord = BlackboardAssetRecord;

export interface IAssetRepository {
  create(asset: BlackboardAssetRecord): Promise<Result<BlackboardAssetRecord, BlackboardError>>;
  findById(assessmentId: AssessmentId, id: AssetId): Promise<Result<BlackboardAssetRecord | null, BlackboardError>>;
  findByParent(assessmentId: AssessmentId, parentId: AssetId): Promise<Result<ReadonlyArray<BlackboardAssetRecord>, BlackboardError>>;
  listByAssessment(
    assessmentId: AssessmentId,
    filter?: { readonly type?: AssetType },
  ): Promise<Result<ReadonlyArray<BlackboardAssetRecord>, BlackboardError>>;
}

// ==========================================
// 3. Observation Models & Repository
// ==========================================

export interface ObservationRecord {
  readonly id: string;
  readonly assessment_id: AssessmentId;
  readonly asset_id: AssetId;
  readonly key: string;
  readonly value: unknown;
  readonly confidence: number;
  readonly source_tool: string;
  readonly agent_id: string;
  readonly evidence_id: string | null;
  readonly is_conflict?: boolean;
  readonly created_at: number;
}

export interface ObservationConflictGroup {
  readonly asset_id: AssetId;
  readonly key: string;
  readonly observations: ReadonlyArray<ObservationRecord>;
}

export interface IObservationRepository {
  record(
    observation: Omit<ObservationRecord, "id" | "is_conflict">,
  ): Promise<Result<ObservationRecord, BlackboardError>>;
  findById(assessmentId: AssessmentId, id: string): Promise<Result<ObservationRecord | null, BlackboardError>>;
  listByAsset(
    assessmentId: AssessmentId,
    assetId: AssetId,
    key?: string,
  ): Promise<Result<ReadonlyArray<ObservationRecord>, BlackboardError>>;
  getConflicts(
    assessmentId: AssessmentId,
    assetId?: AssetId,
  ): Promise<Result<ReadonlyArray<ObservationConflictGroup>, BlackboardError>>;
}

// ==========================================
// 4. Task Models & Repository (Evolved PackBoard)
// ==========================================

export type TaskStatus =
  | "open"
  | "claimed"
  | "in_progress"
  | "completed"
  | "failed"
  | "blocked";

export type TaskPriority = "low" | "normal" | "high" | "critical";

export interface TaskClaim {
  readonly agent_id: string;
  readonly host_id: string;
  readonly pid: number;
  readonly process_start_time: number;
  readonly rea_run_id: string;
  readonly claimed_at: number;
  readonly lease_until: number;
}

export interface TaskRecord {
  readonly id: string;
  readonly assessment_id: AssessmentId;
  readonly task_type: string;
  readonly title: string;
  readonly description: string;
  readonly asset_id: AssetId;
  readonly priority: TaskPriority;
  readonly status: TaskStatus;
  readonly blocked_by: readonly string[];
  readonly fencing_token: number;
  readonly cas_version: number;
  readonly claim: TaskClaim | null;
  readonly result: unknown | null;
  readonly metadata: Readonly<Record<string, unknown>>;
  // Lead compatibility attributes
  readonly fingerprint?: string | undefined;
  readonly location?: FindingLocation | undefined;
  readonly classification?: unknown | undefined;
  readonly severity?: string | undefined;
  readonly confidence?: string | undefined;
  readonly smoke_score?: number | undefined;
  readonly provenance?: string | undefined;
  readonly votes?: readonly unknown[] | undefined;
  readonly evidence_hashes?: readonly string[] | undefined;
  readonly created_at: number;
  readonly updated_at: number;
}

export interface TaskFilter {
  readonly status?: TaskStatus | undefined;
  readonly task_type?: string | undefined;
  readonly asset_id?: AssetId | undefined;
  readonly agent_id?: string | undefined;
}

export interface ITaskRepository {
  create(task: TaskRecord): Promise<Result<TaskRecord, BlackboardError>>;
  getById(assessmentId: AssessmentId, taskId: string): Promise<Result<TaskRecord | null, BlackboardError>>;
  claimTask(
    assessmentId: AssessmentId,
    taskId: string,
    claim: TaskClaim,
    expectedCasVersion: number,
  ): Promise<Result<TaskRecord, BlackboardError>>;
  completeTask(
    assessmentId: AssessmentId,
    taskId: string,
    fencingToken: number,
    result?: unknown,
  ): Promise<Result<TaskRecord, BlackboardError>>;
  failTask(
    assessmentId: AssessmentId,
    taskId: string,
    fencingToken: number,
    errorReason: string,
  ): Promise<Result<TaskRecord, BlackboardError>>;
  updateResult(
    assessmentId: AssessmentId,
    taskId: string,
    fencingToken: number,
    result: unknown,
  ): Promise<Result<TaskRecord, BlackboardError>>;
  reapExpiredLeases(assessmentId: AssessmentId, now: number): Promise<Result<number, BlackboardError>>;
  renewLease(
    assessmentId: AssessmentId,
    taskId: string,
    agentId: string,
    fencingToken: number,
    extensionMs: number,
    maxRenewals?: number,
  ): Promise<Result<TaskRecord, BlackboardError>>;
  retryTask(
    assessmentId: AssessmentId,
    taskId: string,
    reason: string,
    maxRetries?: number,
  ): Promise<Result<{ task: TaskRecord; deadLetter: boolean }, BlackboardError>>;
  listByAssessment(
    assessmentId: AssessmentId,
    filter?: TaskFilter,
  ): Promise<Result<ReadonlyArray<TaskRecord>, BlackboardError>>;
}

// ==========================================
// 5. Agent Registry Models & Repository
// ==========================================

export type AgentStatus = "active" | "idle" | "busy" | "offline" | "crashed";

export interface AgentRegistration {
  readonly agent_id: string;
  readonly assessment_id: AssessmentId;
  readonly capabilities: readonly string[];
  readonly host_id: string;
  readonly pid: number;
  readonly status: AgentStatus;
  readonly heartbeat_at: number;
  readonly registered_at: number;
}

export interface IAgentRegistryRepository {
  register(agent: AgentRegistration): Promise<Result<AgentRegistration, BlackboardError>>;
  heartbeat(
    assessmentId: AssessmentId,
    agentId: string,
    timestamp?: number,
  ): Promise<Result<void, BlackboardError>>;
  updateStatus(
    assessmentId: AssessmentId,
    agentId: string,
    status: AgentStatus,
  ): Promise<Result<void, BlackboardError>>;
  get(assessmentId: AssessmentId, agentId: string): Promise<Result<AgentRegistration | null, BlackboardError>>;
  listActive(
    assessmentId: AssessmentId,
    maxHeartbeatAgeMs?: number,
  ): Promise<Result<ReadonlyArray<AgentRegistration>, BlackboardError>>;
}

// ==========================================
// 6. Finding Models & Repository
// ==========================================

export type FindingState =
  | "CANDIDATE"
  | "INVESTIGATING"
  | "INCONCLUSIVE"
  | "VERIFIED"
  | "FALSE_POSITIVE"
  | "MITIGATED";

export interface FindingRecord {
  readonly id: FindingId;
  readonly assessment_id: AssessmentId;
  readonly fingerprint: string;
  readonly asset_id: AssetId;
  readonly title: string;
  readonly description: string;
  readonly state: FindingState;
  readonly cwe: readonly string[];
  readonly severity: FindingSeverity;
  readonly confidence: FindingConfidence;
  readonly location: FindingLocation;
  readonly evidence_ids: readonly string[];
  readonly remediation: FindingRemediation | null;
  readonly cas_version: number;
  readonly created_at: number;
  readonly updated_at: number;
}

export interface FindingFilter {
  readonly state?: FindingState | undefined;
  readonly asset_id?: AssetId | undefined;
  readonly severity_level?: string | undefined;
}

export interface IFindingRepository {
  create(finding: FindingRecord): Promise<Result<FindingRecord, BlackboardError>>;
  getById(assessmentId: AssessmentId, findingId: FindingId): Promise<Result<FindingRecord | null, BlackboardError>>;
  getByFingerprint(assessmentId: AssessmentId, fingerprint: string): Promise<Result<FindingRecord | null, BlackboardError>>;
  transitionState(
    assessmentId: AssessmentId,
    findingId: FindingId,
    newState: FindingState,
    expectedVersion: number,
    metadata?: Partial<FindingRecord>,
  ): Promise<Result<FindingRecord, BlackboardError>>;
  listByAssessment(
    assessmentId: AssessmentId,
    filter?: FindingFilter,
  ): Promise<Result<ReadonlyArray<FindingRecord>, BlackboardError>>;
}

// ==========================================
// 7. Central Investigation Blackboard Contract
// ==========================================

export interface ICentralBlackboard {
  readonly assessments: IAssessmentRepository;
  readonly assets: IAssetRepository;
  readonly observations: IObservationRepository;
  readonly tasks: ITaskRepository;
  readonly agents: IAgentRegistryRepository;
  readonly findings: IFindingRepository;
  close(): void;
}
