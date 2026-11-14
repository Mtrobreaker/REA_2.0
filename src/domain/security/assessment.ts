import { z } from "zod";
import { digestCanonicalValue } from "../canonicalDigest.js";
import { nulFreeStringSchema } from "../localPath.js";
import { assetRecordSchema, type AssetRecord } from "./asset.js";
import { securityFindingSchema, type SecurityFinding } from "./finding.js";

/**
 * Branded identifier for an assessment session.
 * Format: asm_<sha256>
 */
export type AssessmentId = `asm_${string}`;

export const assessmentIdPattern = /^asm_[a-f0-9]{64}$/u;

export const assessmentIdSchema = z
  .string()
  .regex(assessmentIdPattern, "Invalid Assessment ID (expected asm_<sha256>)")
  .transform((val) => val as AssessmentId);

export const isAssessmentId = (value: unknown): value is AssessmentId =>
  typeof value === "string" && assessmentIdPattern.test(value);

/**
 * Lifecycle phases of an active security assessment.
 */
export const ASSESSMENT_PHASES = [
  "initialization",
  "reconnaissance",
  "vulnerability_discovery",
  "verification",
  "remediation",
  "completed",
  "failed",
] as const;

export type AssessmentPhase = (typeof ASSESSMENT_PHASES)[number];

export const assessmentPhaseSchema = z.enum(ASSESSMENT_PHASES);

/**
 * Depth of security analysis.
 */
export const ASSESSMENT_DEPTHS = ["surface", "standard", "exhaustive"] as const;

export type AssessmentDepth = (typeof ASSESSMENT_DEPTHS)[number];

export const assessmentDepthSchema = z.enum(ASSESSMENT_DEPTHS);

/**
 * Explicit authorization scope governing target engagement.
 * Operates under fail-closed principles: anything not explicitly allowed is forbidden.
 */
export const authorizationScopeSchema = z.strictObject({
  allowed_targets: z
    .array(nulFreeStringSchema)
    .min(1, "At least one target must be explicitly authorized"),
  denied_targets: z.array(nulFreeStringSchema).default([]),
  authorized_by: nulFreeStringSchema,
  authorization_reference: nulFreeStringSchema,
  valid_until: z.string().datetime(),
  allow_active_verification: z.boolean().default(false),
});

export type AuthorizationScope = z.infer<typeof authorizationScopeSchema>;

/**
 * High-level assessment objectives and constraints.
 */
export const assessmentObjectiveSchema = z.strictObject({
  title: nulFreeStringSchema,
  target_technologies: z.array(z.string()).default([]),
  compliance_frameworks: z.array(z.string()).default([]),
  focus_areas: z.array(z.string()).default([]),
  depth: assessmentDepthSchema.default("standard"),
});

export type AssessmentObjective = z.infer<typeof assessmentObjectiveSchema>;

/**
 * High-level metrics summarizing assessment posture.
 */
export const assessmentMetricsSchema = z.strictObject({
  total_assets: z.number().int().nonnegative(),
  total_findings: z.number().int().nonnegative(),
  critical_findings: z.number().int().nonnegative(),
  high_findings: z.number().int().nonnegative(),
  medium_findings: z.number().int().nonnegative(),
  low_findings: z.number().int().nonnegative(),
  info_findings: z.number().int().nonnegative(),
  verified_findings: z.number().int().nonnegative(),
});

export type AssessmentMetrics = z.infer<typeof assessmentMetricsSchema>;

/**
 * Complete immutable snapshot of the Assessment State.
 */
export const assessmentStateSchema = z.strictObject({
  assessment_id: assessmentIdSchema,
  objective: assessmentObjectiveSchema,
  scope: authorizationScopeSchema,
  phase: assessmentPhaseSchema.default("initialization"),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
  completed_at: z.string().datetime().nullable().default(null),
  assets: z.array(assetRecordSchema).default([]),
  findings: z.array(securityFindingSchema).default([]),
  metrics: assessmentMetricsSchema,
});

export type AssessmentState = z.infer<typeof assessmentStateSchema>;

/**
 * Calculate aggregate metrics from assets and findings.
 */
export const calculateAssessmentMetrics = (
  assets: readonly AssetRecord[],
  findings: readonly SecurityFinding[],
): AssessmentMetrics => {
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let info = 0;
  let verified = 0;

  for (const f of findings) {
    switch (f.severity.level) {
      case "CRITICAL":
        critical++;
        break;
      case "HIGH":
        high++;
        break;
      case "MEDIUM":
        medium++;
        break;
      case "LOW":
        low++;
        break;
      case "INFORMATIONAL":
        info++;
        break;
    }
    if (f.verification_status === "VERIFIED") {
      verified++;
    }
  }

  return {
    total_assets: assets.length,
    total_findings: findings.length,
    critical_findings: critical,
    high_findings: high,
    medium_findings: medium,
    low_findings: low,
    info_findings: info,
    verified_findings: verified,
  };
};

/**
 * Deterministically compute an AssessmentId.
 */
export const computeAssessmentId = (input: {
  title: string;
  authorized_by: string;
  created_at: string;
}): AssessmentId => {
  const hash = digestCanonicalValue({
    title: input.title,
    authorized_by: input.authorized_by,
    created_at: input.created_at,
  });
  return `asm_${hash}`;
};

/**
 * Initialize a new AssessmentState with valid metrics.
 */
export const createAssessmentState = (input: {
  objective: AssessmentObjective;
  scope: AuthorizationScope;
  now?: string;
}): AssessmentState => {
  const timestamp = input.now ?? new Date().toISOString();
  const assessment_id = computeAssessmentId({
    title: input.objective.title,
    authorized_by: input.scope.authorized_by,
    created_at: timestamp,
  });

  return {
    assessment_id,
    objective: input.objective,
    scope: input.scope,
    phase: "initialization",
    created_at: timestamp,
    updated_at: timestamp,
    completed_at: null,
    assets: [],
    findings: [],
    metrics: {
      total_assets: 0,
      total_findings: 0,
      critical_findings: 0,
      high_findings: 0,
      medium_findings: 0,
      low_findings: 0,
      info_findings: 0,
      verified_findings: 0,
    },
  };
};

