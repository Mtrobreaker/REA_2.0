import { z } from "zod";
import {
  localPathStringSchema,
  nulFreeStringSchema,
} from "../domain/localPath.js";
import {
  assessmentDepthSchema,
  assessmentIdSchema,
} from "../domain/security/assessment.js";
import { assetRecordSchema } from "../domain/security/asset.js";
import {
  findingIdSchema,
  securityFindingSchema,
} from "../domain/security/finding.js";

/**
 * Input schema to start an authorized security assessment.
 */
export const startSecurityAssessmentSchema = z.strictObject({
  title: nulFreeStringSchema.describe(
    "Title or name of the cybersecurity assessment",
  ),
  allowed_targets: z
    .array(nulFreeStringSchema)
    .min(1)
    .describe(
      "Explicitly authorized target paths, IPs, domains, or repositories",
    ),
  denied_targets: z
    .array(nulFreeStringSchema)
    .default([])
    .describe("Explicitly forbidden targets within the scope"),
  authorized_by: nulFreeStringSchema.describe(
    "Authorizing entity, asset owner, or compliance authority",
  ),
  authorization_reference: nulFreeStringSchema.describe(
    "Written authorization ticket, contract, or reference identifier",
  ),
  valid_until: z
    .string()
    .datetime()
    .describe("ISO-8601 expiration timestamp of authorization"),
  allow_active_verification: z
    .boolean()
    .default(false)
    .describe(
      "Whether active, non-destructive reproduction in sandboxes is permitted",
    ),
  target_technologies: z
    .array(z.string())
    .default([])
    .describe(
      "Specific technologies under assessment (e.g. firmware, c, embedded_linux)",
    ),
  compliance_frameworks: z
    .array(z.string())
    .default([])
    .describe(
      "Applicable compliance frameworks (e.g. OWASP_TOP_10, CWE_TOP_25)",
    ),
  depth: assessmentDepthSchema
    .default("standard")
    .describe("Analysis depth: surface, standard, or exhaustive"),
});

export type StartSecurityAssessmentInput = z.infer<
  typeof startSecurityAssessmentSchema
>;

/**
 * Input schema to query the current state of an assessment.
 */
export const getSecurityAssessmentStateSchema = z.strictObject({
  assessment_id: assessmentIdSchema.describe(
    "Unique identifier of the assessment (asm_<sha256>)",
  ),
});

export type GetSecurityAssessmentStateInput = z.infer<
  typeof getSecurityAssessmentStateSchema
>;

/**
 * Input schema to add or record an asset under assessment.
 */
export const registerSecurityAssetSchema = z.strictObject({
  assessment_id: assessmentIdSchema.describe(
    "Assessment session to register asset in",
  ),
  asset: assetRecordSchema.describe("Asset record definition"),
});

export type RegisterSecurityAssetInput = z.infer<
  typeof registerSecurityAssetSchema
>;

/**
 * Input schema to manually record or update a security finding.
 */
export const recordSecurityFindingSchema = z.strictObject({
  assessment_id: assessmentIdSchema.describe(
    "Assessment session to record finding in",
  ),
  finding: securityFindingSchema.describe(
    "Full 15-point explainable security finding object",
  ),
});

export type RecordSecurityFindingInput = z.infer<
  typeof recordSecurityFindingSchema
>;

/**
 * Input schema to verify a security finding candidate.
 */
export const verifySecurityFindingSchema = z.strictObject({
  assessment_id: assessmentIdSchema.describe("Assessment session"),
  finding_id: findingIdSchema.describe(
    "Finding identifier to verify (fnd_<sha256>)",
  ),
  reproduction_command: z
    .string()
    .optional()
    .describe("Optional specific test command to execute in sandbox"),
});

export type VerifySecurityFindingInput = z.infer<
  typeof verifySecurityFindingSchema
>;

/**
 * Input schema to calculate CVSS v3.1 score from vector.
 */
export const calculateCvssSchema = z.strictObject({
  vector_string: z
    .string()
    .startsWith("CVSS:3.1/")
    .describe(
      "Standard CVSS v3.1 vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    ),
});

export type CalculateCvssInput = z.infer<typeof calculateCvssSchema>;

/**
 * Input schema to generate an explainable cybersecurity report.
 */
export const generateSecurityReportSchema = z.strictObject({
  assessment_id: assessmentIdSchema.describe(
    "Assessment to generate report for",
  ),
  format: z
    .enum(["markdown", "json", "sarif", "html"])
    .default("markdown")
    .describe("Target report format"),
  include_remediation_diffs: z
    .boolean()
    .default(true)
    .describe("Whether to include unified code/config patches in the report"),
});

export type GenerateSecurityReportInput = z.infer<
  typeof generateSecurityReportSchema
>;

/**
 * Input schema to scan an authorized target using the vulnerability engine.
 */
export const scanSecurityTargetSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute local target file or directory path to inspect",
  ),
  authorized_by: nulFreeStringSchema
    .default("mcp-caller")
    .describe("Authorizing entity name or role"),
  authorization_reference: nulFreeStringSchema
    .default("MCP-ENGAGEMENT")
    .describe("Authorization ticket or reference ID"),
  depth: assessmentDepthSchema
    .default("standard")
    .describe("Assessment depth: surface, standard, or exhaustive"),
  format: z
    .enum(["markdown", "json", "sarif", "html"])
    .default("markdown")
    .describe("Output report format"),
});

export type ScanSecurityTargetInput = z.infer<typeof scanSecurityTargetSchema>;

/**
 * Input schema to perform deep firmware security inspection.
 */
export const deepFirmwareInspectionSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute local firmware binary path to analyze",
  ),
});

export type DeepFirmwareInspectionInput = z.infer<
  typeof deepFirmwareInspectionSchema
>;

/**
 * Input schema to inspect device hardware-to-software communication interfaces.
 */
export const deviceInspectionSchema = z.strictObject({
  target: nulFreeStringSchema.describe(
    "Device target identifier, COM/TTY port, ADB serial, or local interface descriptor",
  ),
  interface_type: z
    .enum(["UART_SERIAL", "ADB", "JTAG_SWD", "USB"])
    .optional()
    .describe("Specific interface type to inspect"),
});

export type DeviceInspectionInput = z.infer<typeof deviceInspectionSchema>;

/**
 * Input schema to audit embedded operating system security.
 */
export const embeddedOsAuditSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute local path to extracted root filesystem or mounted OS image",
  ),
});

export type EmbeddedOsAuditInput = z.infer<typeof embeddedOsAuditSchema>;

/**
 * Input schema to run full 10-agent multi-agent security assessment.
 */
export const runMultiAgentAssessmentSchema = z.strictObject({
  target_path: localPathStringSchema.describe(
    "Absolute local path of the asset, directory, or repository to assess",
  ),
  title: nulFreeStringSchema
    .default("Multi-Agent Cybersecurity Assessment")
    .describe("Assessment objective title"),
  authorized_by: nulFreeStringSchema
    .default("mcp-security-lead")
    .describe("Authorizing officer identity"),
  authorization_reference: nulFreeStringSchema
    .default("MCP-TASK-AUTH")
    .describe("Authorization reference ticket"),
  depth: assessmentDepthSchema.default("standard").describe("Assessment depth"),
  format: z
    .enum(["markdown", "json", "sarif", "html"])
    .default("markdown")
    .describe("Output report format"),
});

export type RunMultiAgentAssessmentInput = z.infer<
  typeof runMultiAgentAssessmentSchema
>;

export const hardwareRtlInspectionSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute local file or device path to analyze",
  ),
});
export type HardwareRtlInspectionInput = z.infer<
  typeof hardwareRtlInspectionSchema
>;
