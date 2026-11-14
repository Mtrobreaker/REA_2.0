import type {
  AssessmentObjective,
  AssessmentState,
  AuthorizationScope,
} from "../../domain/security/assessment.js";
import type { AssetRecord } from "../../domain/security/asset.js";
import type { SecurityFinding } from "../../domain/security/finding.js";
import type { Result } from "../../domain/result.js";

/**
 * 10 Specialized Security Agent Roles.
 */
export const AGENT_ROLES = [
  "orchestrator",
  "reconnaissance",
  "software_security",
  "binary_analysis",
  "firmware_security",
  "hardware_security",
  "malware_analysis",
  "verification",
  "threat_intelligence",
  "remediation",
] as const;

export type AgentRole = (typeof AGENT_ROLES)[number];

/**
 * Structured Agent-to-Agent Communication Message.
 */
export interface AgentMessage {
  readonly message_id: string;
  readonly sender: AgentRole;
  readonly recipient: AgentRole | "all";
  readonly timestamp: string;
  readonly kind:
    | "TASK_ASSIGNMENT"
    | "TASK_COMPLETION"
    | "TASK_FAILURE"
    | "FINDING_PROPOSAL"
    | "FINDING_VALIDATION"
    | "EVIDENCE_ATTACHED"
    | "CORRELATION_REQUEST"
    | "REMEDIATION_REQUEST";
  readonly payload: unknown;
}

/**
 * Shared Context provided to agents during execution.
 */
export interface AgentContext {
  readonly state: AssessmentState;
  readonly messages: readonly AgentMessage[];
  readonly signal?: AbortSignal | undefined;
  readonly postMessage: (message: Omit<AgentMessage, "message_id" | "timestamp">) => void;
  readonly updateAssessment: (updater: (draft: AssessmentState) => AssessmentState) => void;
  readonly packboard?: import("../../domain/security/packboard/types.js").PackBoardStore | undefined;
}

export interface AgentExecutionResult {
  readonly agent_role: AgentRole;
  readonly actions_performed: readonly string[];
  readonly findings_added: readonly SecurityFinding[];
  readonly findings_modified: readonly SecurityFinding[];
  readonly assets_added: readonly AssetRecord[];
}

export interface AgentExecutionError {
  readonly agent_role: AgentRole;
  readonly code: string;
  readonly message: string;
  readonly cause?: unknown;
}

/**
 * Generic Interface for all Specialized Security Agents.
 */
export interface SecurityAgent {
  readonly role: AgentRole;
  readonly name: string;
  readonly description: string;
  execute(
    context: AgentContext,
  ): Promise<Result<AgentExecutionResult, AgentExecutionError>>;
}

