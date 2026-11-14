import { z } from "zod";
import { digestCanonicalValue } from "../canonicalDigest.js";
import { nulFreeStringSchema } from "../localPath.js";
import {
  assetIdSchema,
  assetTypeSchema,
  type AssetId,
  type AssetType,
} from "./asset.js";
import {
  exploitabilityTierSchema,
  remediationPrioritySchema,
  securityClassificationSchema,
  securityConfidenceLevelSchema,
  securitySeverityLevelSchema,
  verificationStatusSchema,
  type ExploitabilityTier,
  type RemediationPriority,
  type SecurityClassification,
  type SecurityConfidenceLevel,
  type SecuritySeverityLevel,
  type VerificationStatus,
} from "./classification.js";

/**
 * Branded identifier for an identified security finding.
 * Format: fnd_<sha256>
 */
export type FindingId = `fnd_${string}`;

export const findingIdPattern = /^fnd_[a-f0-9]{64}$/u;

export const findingIdSchema = z
  .string()
  .regex(findingIdPattern, "Invalid Finding ID (expected fnd_<sha256>)")
  .transform((val) => val as FindingId);

export const isFindingId = (value: unknown): value is FindingId =>
  typeof value === "string" && findingIdPattern.test(value);

/**
 * Spatial coordinate of the vulnerability in source, binary, or hardware.
 */
export const findingLocationSchema = z.strictObject({
  file: nulFreeStringSchema.nullable().default(null),
  function: z.string().nullable().default(null),
  line: z.number().int().min(1).nullable().default(null),
  column: z.number().int().min(1).nullable().default(null),
  end_line: z.number().int().min(1).nullable().default(null),
  module: z.string().nullable().default(null),
  component: z.string().nullable().default(null),
  address: z
    .string()
    .regex(/^0x[a-fA-F0-9]+$/u, "Invalid hex address")
    .nullable()
    .default(null),
  offset: z.number().int().nonnegative().nullable().default(null),
});

export type FindingLocation = z.infer<typeof findingLocationSchema>;

/**
 * Impact assessment detailing potential consequences and exploitability.
 */
export const findingImpactSchema = z.strictObject({
  description: z.string().min(1),
  attack_prerequisites: z.array(z.string()).default([]),
  exploitability: exploitabilityTierSchema.default("UNKNOWN"),
});

export type FindingImpact = z.infer<typeof findingImpactSchema>;

/**
 * Severity assessment including qualitative level and CVSS vector/score.
 */
export const findingSeveritySchema = z.strictObject({
  level: securitySeverityLevelSchema,
  cvss_vector: z.string().nullable().default(null),
  cvss_score: z.number().min(0).max(10).nullable().default(null),
  justification: z.string().default(""),
});

export type FindingSeverity = z.infer<typeof findingSeveritySchema>;

/**
 * Confidence assessment including false-positive considerations.
 */
export const findingConfidenceSchema = z.strictObject({
  level: securityConfidenceLevelSchema,
  false_positive_considerations: z.array(z.string()).default([]),
  verification_method: z.string().nullable().default(null),
});

export type FindingConfidence = z.infer<typeof findingConfidenceSchema>;

/**
 * Remediation plan providing actionable fix guidance, patch, and validation procedure.
 */
export const findingRemediationSchema = z.strictObject({
  description: z.string().min(1),
  code_diff: z.string().nullable().default(null),
  config_example: z.string().nullable().default(null),
  priority: remediationPrioritySchema.default("MEDIUM_TERM"),
  validation_procedure: z.string().default(""),
});

export type FindingRemediation = z.infer<typeof findingRemediationSchema>;

/**
 * Provenance tracking discovery and verification chain.
 */
export const findingProvenanceSchema = z.strictObject({
  discovered_by: z.string().min(1),
  discovered_at: z.string().datetime(),
  verified_by: z.string().nullable().default(null),
  verified_at: z.string().datetime().nullable().default(null),
});

export type FindingProvenance = z.infer<typeof findingProvenanceSchema>;

/**
 * Complete 15-Point Explainable Security Finding Schema.
 */
export const securityFindingSchema = z.strictObject({
  id: findingIdSchema,
  name: z.string().min(1),
  affected_asset: z.strictObject({
    id: assetIdSchema,
    name: nulFreeStringSchema,
    type: assetTypeSchema,
  }),
  location: findingLocationSchema,
  technical_description: z.string().min(1),
  root_cause: z.string().min(1),
  evidence_ids: z
    .array(z.string().regex(/^ev_[a-f0-9]{64}$/u))
    .default([]),
  reproduction_steps: z.array(z.string()).default([]),
  impact: findingImpactSchema,
  severity: findingSeveritySchema,
  confidence: findingConfidenceSchema,
  remediation: findingRemediationSchema,
  classification: securityClassificationSchema.default(() => ({
    cve: [],
    cwe: [],
    capec: [],
    mitre_attack: [],
    owasp: [],
  })),
  verification_status: verificationStatusSchema.default("UNVERIFIED"),
  provenance: findingProvenanceSchema,
});

export type SecurityFinding = z.infer<typeof securityFindingSchema>;

/**
 * Deterministically compute a unique FindingId from its invariant semantic core.
 */
export const computeFindingId = (input: {
  asset_id: AssetId;
  name: string;
  location: FindingLocation;
  root_cause: string;
}): FindingId => {
  const semanticCore = {
    asset_id: input.asset_id,
    name: input.name,
    location: {
      file: input.location.file,
      function: input.location.function,
      line: input.location.line,
      address: input.location.address,
      offset: input.location.offset,
    },
    root_cause: input.root_cause,
  };
  const hash = digestCanonicalValue(semanticCore);
  return `fnd_${hash}`;
};
