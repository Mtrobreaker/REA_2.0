import { z } from "zod";

/**
 * Branded type for Common Vulnerabilities and Exposures (CVE) identifier.
 * Pattern: CVE-YYYY-NNNN... (e.g. CVE-2024-1234, CVE-2021-44228)
 */
export type CveId = string & { readonly __brand: "CveId" };

export const cveIdPattern = /^CVE-\d{4}-\d{4,}$/u;

export const cveIdSchema = z
  .string()
  .regex(cveIdPattern, "Invalid CVE identifier format (expected CVE-YYYY-NNNN...)")
  .transform((val) => val as CveId);

export const isCveId = (value: unknown): value is CveId =>
  typeof value === "string" && cveIdPattern.test(value);

/**
 * Branded type for Common Weakness Enumeration (CWE) identifier.
 * Pattern: CWE-NNN... (e.g. CWE-79, CWE-89, CWE-119)
 */
export type CweId = string & { readonly __brand: "CweId" };

export const cweIdPattern = /^CWE-\d+$/u;

export const cweIdSchema = z
  .string()
  .regex(cweIdPattern, "Invalid CWE identifier format (expected CWE-NNN)")
  .transform((val) => val as CweId);

export const isCweId = (value: unknown): value is CweId =>
  typeof value === "string" && cweIdPattern.test(value);

/**
 * Branded type for Common Attack Pattern Enumeration and Classification (CAPEC) identifier.
 * Pattern: CAPEC-NNN... (e.g. CAPEC-100, CAPEC-66)
 */
export type CapecId = string & { readonly __brand: "CapecId" };

export const capecIdPattern = /^CAPEC-\d+$/u;

export const capecIdSchema = z
  .string()
  .regex(capecIdPattern, "Invalid CAPEC identifier format (expected CAPEC-NNN)")
  .transform((val) => val as CapecId);

export const isCapecId = (value: unknown): value is CapecId =>
  typeof value === "string" && capecIdPattern.test(value);

/**
 * Branded type for MITRE ATT&CK technique or sub-technique identifier.
 * Pattern: T1234 or T1234.001
 */
export type MitreAttackTechniqueId = string & {
  readonly __brand: "MitreAttackTechniqueId";
};

export const mitreAttackTechniquePattern = /^T\d{4}(?:\.\d{3})?$/u;

export const mitreAttackTechniqueSchema = z
  .string()
  .regex(
    mitreAttackTechniquePattern,
    "Invalid MITRE ATT&CK technique format (expected TNNNN or TNNNN.NNN)",
  )
  .transform((val) => val as MitreAttackTechniqueId);

export const isMitreAttackTechniqueId = (
  value: unknown,
): value is MitreAttackTechniqueId =>
  typeof value === "string" && mitreAttackTechniquePattern.test(value);

/**
 * OWASP Top 10 (Web 2021) Categories.
 */
export const OWASP_WEB_2021_CATEGORIES = [
  "A01:2021-Broken Access Control",
  "A02:2021-Cryptographic Failures",
  "A03:2021-Injection",
  "A04:2021-Insecure Design",
  "A05:2021-Security Misconfiguration",
  "A06:2021-Vulnerable and Outdated Components",
  "A07:2021-Identification and Authentication Failures",
  "A08:2021-Software and Data Integrity Failures",
  "A09:2021-Security Logging and Monitoring Failures",
  "A10:2021-Server-Side Request Forgery",
] as const;

export type OwaspWeb2021Category = (typeof OWASP_WEB_2021_CATEGORIES)[number];

export const owaspWeb2021CategorySchema = z.enum(OWASP_WEB_2021_CATEGORIES);

/**
 * Standard qualitative severity levels following CVSS / NIST conventions.
 */
export const SECURITY_SEVERITY_LEVELS = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFORMATIONAL",
] as const;

export type SecuritySeverityLevel = (typeof SECURITY_SEVERITY_LEVELS)[number];

export const securitySeverityLevelSchema = z.enum(SECURITY_SEVERITY_LEVELS);

/**
 * Epistemic confidence levels for security findings.
 */
export const SECURITY_CONFIDENCE_LEVELS = [
  "CONFIRMED",
  "HIGH",
  "MEDIUM",
  "LOW",
  "TENTATIVE",
] as const;

export type SecurityConfidenceLevel =
  (typeof SECURITY_CONFIDENCE_LEVELS)[number];

export const securityConfidenceLevelSchema = z.enum(SECURITY_CONFIDENCE_LEVELS);

/**
 * Authoritative 6-state Vulnerability Lifecycle (rea-t3mp3st-integration-blueprint.md).
 * Canonical states:
 * - CANDIDATE: Initial hypothesis from L1 (lexical) or L2 (heuristic) detectors.
 * - INVESTIGATING: Active multi-stage adjudication or verification in progress.
 * - INCONCLUSIVE: Verification attempted but inconclusive (guards unclear, depth limit, no L3/L4/L5 proof).
 * - VERIFIED: Conclusively verified with L3 (reachability), L4 (taint/dataflow), or L5 (witness/PoC) evidence.
 * - FALSE_POSITIVE: Proven unreachable, disproven hypothesis, or sanitized.
 * - MITIGATED: Verified vulnerability with validated defensive remediation applied.
 *
 * Evidence rules:
 * - L1 (lexical) and L2 (heuristic) can produce CANDIDATE findings.
 * - L1/L2 alone CANNOT mark a finding VERIFIED.
 * - VERIFIED requires L3 (reachability), L4 (taint/dataflow), or L5 (witness/PoC) evidence.
 */
export const VULNERABILITY_LIFECYCLE_STATES = [
  "CANDIDATE",
  "INVESTIGATING",
  "INCONCLUSIVE",
  "VERIFIED",
  "FALSE_POSITIVE",
  "MITIGATED",
] as const;

export type VulnerabilityLifecycleState =
  (typeof VULNERABILITY_LIFECYCLE_STATES)[number];

export const vulnerabilityLifecycleStateSchema = z.enum(
  VULNERABILITY_LIFECYCLE_STATES,
);

/**
 * Verification state of an identified vulnerability candidate.
 * Aligned with the canonical vulnerability lifecycle.
 */
export const VERIFICATION_STATUSES = [
  "CANDIDATE",
  "INVESTIGATING",
  "INCONCLUSIVE",
  "VERIFIED",
  "FALSE_POSITIVE",
  "MITIGATED",
  "UNVERIFIED",
  "DISPUTED",
] as const;

export type VerificationStatus = (typeof VERIFICATION_STATUSES)[number];

export const verificationStatusSchema = z.enum(VERIFICATION_STATUSES);

/**
 * Exploitability feasibility assessment.
 */
export const EXPLOITABILITY_TIERS = [
  "PROVEN",
  "THEORETICAL",
  "UNPROVEN",
  "UNKNOWN",
] as const;

export type ExploitabilityTier = (typeof EXPLOITABILITY_TIERS)[number];

export const exploitabilityTierSchema = z.enum(EXPLOITABILITY_TIERS);

/**
 * Remediation urgency priority.
 */
export const REMEDIATION_PRIORITIES = [
  "IMMEDIATE",
  "SHORT_TERM",
  "MEDIUM_TERM",
  "LONG_TERM",
] as const;

export type RemediationPriority = (typeof REMEDIATION_PRIORITIES)[number];

export const remediationPrioritySchema = z.enum(REMEDIATION_PRIORITIES);

/**
 * Aggregated Security Classification taxonomy record.
 */
export const securityClassificationSchema = z.strictObject({
  cve: z.array(cveIdSchema).default([]),
  cwe: z.array(cweIdSchema).default([]),
  capec: z.array(capecIdSchema).default([]),
  mitre_attack: z.array(mitreAttackTechniqueSchema).default([]),
  owasp: z.array(z.string()).default([]),
});

export type SecurityClassification = z.infer<
  typeof securityClassificationSchema
>;

