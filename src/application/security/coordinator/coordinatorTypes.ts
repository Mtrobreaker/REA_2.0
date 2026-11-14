import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { TaskRecord } from "../../../domain/security/blackboard/types.js";
import type { TaskContextProjection } from "../../../domain/security/blackboard/contextProjection.js";

export interface WorkerConfig {
  readonly agentId: string;
  readonly assessmentId: AssessmentId;
  readonly capabilities: readonly string[];
  readonly hostId?: string | undefined;
  readonly pid?: number | undefined;
  readonly pollIntervalMs?: number | undefined;
  readonly leaseDurationMs?: number | undefined;
  readonly heartbeatIntervalMs?: number | undefined;
  readonly taskTimeoutMs?: number | undefined;
  readonly maxTaskCeilingRenewals?: number | undefined;
  readonly maxRetries?: number | undefined;
}

export type TaskExecutionHandler = (
  task: TaskRecord,
  context: TaskContextProjection,
  signal: AbortSignal,
) => Promise<unknown>;

export interface OrchestratorConfig {
  readonly maxConcurrency?: number | undefined; // default 4, capped at 16
  readonly reapIntervalMs?: number | undefined;
  readonly defaultMaxRetries?: number | undefined;
}

export interface AgentHealthInfo {
  readonly agent_id: string;
  readonly status: string;
  readonly heartbeat_at: number;
  readonly pid: number;
  readonly host_id: string;
}

export interface ObservabilitySnapshot {
  readonly assessment_id: string;
  readonly registered_agents: number;
  readonly active_workers: number;
  readonly pending_tasks: number;
  readonly running_tasks: number;
  readonly completed_tasks: number;
  readonly failed_tasks: number;
  readonly dead_letter_tasks: number;
  readonly expired_leases_reaped: number;
  readonly agent_health: ReadonlyArray<AgentHealthInfo>;
}

