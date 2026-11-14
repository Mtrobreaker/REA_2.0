import { z } from "zod";
import type { AssessmentId } from "../assessment.js";
import type { AssetId } from "../asset.js";
import {
  findingLocationSchema,
  type FindingId,
  type FindingLocation,
} from "../finding.js";
import {
  securityClassificationSchema,
  securityConfidenceLevelSchema,
  securitySeverityLevelSchema,
  type SecurityClassification,
  type SecurityConfidenceLevel,
  type SecuritySeverityLevel,
} from "../classification.js";

/**
 * Branded identifier for a PackBoard Lead.
 * Pattern: lead_<sha256>
 */
export type LeadId = `lead_${string}`;

export const leadIdPattern = /^lead_[a-f0-9]{64}$/u;

export const leadIdSchema = z
  .string()
  .regex(leadIdPattern, "Invalid Lead ID (expected lead_<sha256>)")
  .transform((val) => val as LeadId);

export const isLeadId = (value: unknown): value is LeadId =>
  typeof value === "string" && leadIdPattern.test(value);

/**
 * Lifecycle status of a security lead on the blackboard.
 */
export const LEAD_STATUSES = [
  "open",
  "claimed",
  "investigating",
  "verified",
  "mitigated",
  "false_positive",
  "disputed",
] as const;

export type LeadStatus = (typeof LEAD_STATUSES)[number];

export const leadStatusSchema = z.enum(LEAD_STATUSES);

/**
 * Provenance origin of the discovered lead.
 */
export const LEAD_PROVENANCES = [
  "source_scan",
  "endpoint_discovery",
  "fuzz_result",
  "intel_feed",
  "manual",
  "agent_inference",
  "binary_decompilation",
  "firmware_extraction",
] as const;

export type LeadProvenance = (typeof LEAD_PROVENANCES)[number];

export const leadProvenanceSchema = z.enum(LEAD_PROVENANCES);

/**
 * Process ownership and lease details for an active claim.
 * Uses REA's 4-tuple process identity to prevent PID reuse vulnerabilities.
 */
export interface LeadClaim {
  readonly agent_id: string;
  readonly host_id: string;
  readonly pid: number;
  readonly process_start_time: number;
  readonly rea_run_id: string;
  readonly claimed_at: number;
  readonly lease_until: number;
}

export const leadClaimSchema = z.strictObject({
  agent_id: z.string().min(1),
  host_id: z.string().min(1),
  pid: z.number().int().positive(),
  process_start_time: z.number().int().nonnegative(),
  rea_run_id: z.string().min(1),
  claimed_at: z.number().int().nonnegative(),
  lease_until: z.number().int().nonnegative(),
});

/**
 * An agent's verification or refutation vote on a lead.
 */
export interface LeadVote {
  readonly agent_id: string;
  readonly verdict: "CONFIRMED" | "REFUTED" | "INCONCLUSIVE";
  readonly confidence: number; // 0.00 to 1.00
  readonly reasoning: string;
  readonly voted_at: number;
  readonly evidence_hashes: readonly string[];
}

export const leadVoteSchema = z.strictObject({
  agent_id: z.string().min(1),
  verdict: z.enum(["CONFIRMED", "REFUTED", "INCONCLUSIVE"]),
  confidence: z.number().min(0).max(1),
  reasoning: z.string().min(1),
  voted_at: z.number().int().nonnegative(),
  evidence_hashes: z.array(z.string()).default([]),
});

/**
 * Core security lead on the multi-agent PackBoard blackboard.
 */
export interface Lead {
  readonly id: LeadId;
  readonly assessment_id: AssessmentId;
  readonly fingerprint: string;
  readonly title: string;
  readonly description: string;
  readonly asset_id: AssetId;
  readonly location: FindingLocation;
  readonly classification: SecurityClassification;
  readonly severity: SecuritySeverityLevel;
  readonly confidence: SecurityConfidenceLevel;
  readonly status: LeadStatus;
  readonly smoke_score: number;
  readonly cas_version: number;
  readonly provenance: LeadProvenance;
  readonly claim: LeadClaim | null;
  readonly votes: readonly LeadVote[];
  readonly evidence_hashes: readonly string[];
  readonly created_at: number;
  readonly updated_at: number;
}

export const leadSchema = z.strictObject({
  id: leadIdSchema,
  assessment_id: z.string().startsWith("asm_") as unknown as z.ZodType<AssessmentId>,
  fingerprint: z.string().length(64),
  title: z.string().min(1),
  description: z.string().min(1),
  asset_id: z.string().startsWith("ast_") as unknown as z.ZodType<AssetId>,
  location: findingLocationSchema,
  classification: securityClassificationSchema,
  severity: securitySeverityLevelSchema,
  confidence: securityConfidenceLevelSchema,
  status: leadStatusSchema,
  smoke_score: z.number().int().nonnegative().default(1),
  cas_version: z.number().int().nonnegative().default(1),
  provenance: leadProvenanceSchema,
  claim: leadClaimSchema.nullable().default(null),
  votes: z.array(leadVoteSchema).default([]),
  evidence_hashes: z.array(z.string()).default([]),
  created_at: z.number().int().nonnegative(),
  updated_at: z.number().int().nonnegative(),
});

/**
 * Filter criteria when querying leads.
 */
export interface LeadFilter {
  readonly status?: LeadStatus | readonly LeadStatus[];
  readonly severity?: SecuritySeverityLevel | readonly SecuritySeverityLevel[];
  readonly asset_id?: AssetId;
  readonly claimed_by?: string;
  readonly unclaimed_only?: boolean;
}

/**
 * Abstract persistence store interface for PackBoard.
 * Implemented in infrastructure layer (e.g. SQLite WAL).
 */
export interface PackBoardStore {
  postLead(lead: Lead): Promise<import("../../result.js").Result<Lead, import("./errors.js").PackBoardStoreError>>;
  getLead(
    assessmentId: AssessmentId,
    leadId: LeadId,
  ): Promise<import("../../result.js").Result<Lead | null, import("./errors.js").PackBoardStoreError>>;
  claimLead(
    assessmentId: AssessmentId,
    leadId: LeadId,
    claim: LeadClaim,
    expectedVersion: number,
  ): Promise<
    import("../../result.js").Result<
      Lead,
      import("./errors.js").PackBoardCasConflictError | import("./errors.js").PackBoardStoreError
    >
  >;
  extendLease(
    assessmentId: AssessmentId,
    leadId: LeadId,
    claimant: LeadClaim,
    additionalSeconds: number,
  ): Promise<import("../../result.js").Result<Lead, import("./errors.js").PackBoardStoreError>>;
  releaseClaim(
    assessmentId: AssessmentId,
    leadId: LeadId,
    agentId: string,
    finalStatus?: LeadStatus,
  ): Promise<import("../../result.js").Result<Lead, import("./errors.js").PackBoardStoreError>>;
  voteLead(
    assessmentId: AssessmentId,
    leadId: LeadId,
    vote: LeadVote,
    expectedVersion: number,
  ): Promise<
    import("../../result.js").Result<
      Lead,
      import("./errors.js").PackBoardCasConflictError | import("./errors.js").PackBoardStoreError
    >
  >;
  listLeads(
    assessmentId: AssessmentId,
    filter?: LeadFilter,
  ): Promise<import("../../result.js").Result<readonly Lead[], import("./errors.js").PackBoardStoreError>>;
  reapExpiredLeases(
    assessmentId: AssessmentId,
    now?: number,
  ): Promise<import("../../result.js").Result<number, import("./errors.js").PackBoardStoreError>>;
}

