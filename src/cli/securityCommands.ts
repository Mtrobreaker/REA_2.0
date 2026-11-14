import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import { basename } from "node:path";
import { z } from "incur";
import type { Logger } from "pino";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import {
  assessmentStateSchema,
  calculateAssessmentMetrics,
  createAssessmentState,
  type AssessmentDepth,
  type AssessmentState,
} from "../domain/security/assessment.js";
import {
  computeAssetId,
  type AssetRecord,
  type AssetType,
} from "../domain/security/asset.js";
import { calculateCvss31FromVector } from "../domain/security/cvssCalculator.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { VulnerabilityEngine } from "../security/engines/vulnerability/engine.js";
import {
  defaultReportGenerator,
  type ReportFormat,
} from "../security/reporting/reportGenerator.js";
import { withCommandCancellation } from "./commandCancellation.js";
import type { CliInstance } from "./types.js";

/**
 * Register cybersecurity CLI commands:
 * - rea security-scan <target> [--format=markdown|json|sarif|html] [--output=<file>]
 * - rea security-cvss <vector>
 * - rea security-report <file> [--format=markdown|json|sarif|html] [--output=<file>]
 */
export const registerSecurityCommands = (
  cli: CliInstance,
  logger: Logger,
  _environment: Readonly<Record<string, string | undefined>>,
): void => {
  const engine = new VulnerabilityEngine();

  // 1. rea security-scan
  cli.command(CLI_COMMANDS.securityScan, {
    description:
      "Perform vulnerability discovery and security posture assessment on an authorized target",
    args: z.object({
      path: z
        .string()
        .describe("Target file or directory path to inspect and assess"),
    }),
    options: z.object({
      format: z
        .enum(["markdown", "json", "sarif", "html"])
        .default("markdown")
        .describe("Output report format"),
      output: z
        .string()
        .optional()
        .describe("Optional output file destination"),
      depth: z
        .enum(["surface", "standard", "exhaustive"])
        .default("standard")
        .describe("Depth of analysis"),
      authorizedBy: z
        .string()
        .default("cli-operator")
        .describe("Authorizing entity name or role"),
      reference: z
        .string()
        .default("CLI-ENGAGEMENT")
        .describe("Authorization ticket or reference ID"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) =>
        logCliCommand(logger, CLI_COMMANDS.securityScan, async () => {
          const targetPath = absoluteCallerPath(args.path);
          const targetStats = await stat(targetPath);

          let assetType: AssetType = "source_repository";
          if (targetStats.isFile()) {
            const lower = targetPath.toLowerCase();
            if (
              lower.endsWith(".bin") ||
              lower.endsWith(".img") ||
              lower.endsWith(".rom") ||
              lower.endsWith(".fw")
            ) {
              assetType = "firmware_image";
            } else {
              assetType = "compiled_binary";
            }
          }

          const assetName = basename(targetPath);
          const assetId = computeAssetId({
            name: assetName,
            type: assetType,
          });

          const asset: AssetRecord = {
            id: assetId,
            name: assetName,
            type: assetType,
            path: targetPath,
            digest: null,
            architecture: null,
            version: null,
            environment: null,
            tags: ["cli-target"],
            metadata: {
              format: targetStats.isDirectory() ? "directory" : "binary",
            },
          };

          const scope = {
            allowed_targets: [targetPath],
            denied_targets: [],
            authorized_by: options.authorizedBy,
            authorization_reference: options.reference,
            valid_until: new Date(Date.now() + 86_400_000).toISOString(),
            allow_active_verification: false,
          };

          const initialAssessment = createAssessmentState({
            objective: {
              title: `Security Assessment of ${assetName}`,
              target_technologies: [],
              compliance_frameworks: [],
              focus_areas: ["Vulnerability Discovery", "Static Analysis"],
              depth: options.depth as AssessmentDepth,
            },
            scope,
          });

          const discoveryResult = await engine.discover({
            asset,
            scope,
            signal,
          });

          if (!discoveryResult.ok) {
            return {
              status: "FAILED",
              error: discoveryResult.error,
            };
          }

          const findings = discoveryResult.value.findings;
          const metrics = calculateAssessmentMetrics([asset], findings);

          const completedAssessment: AssessmentState = {
            ...initialAssessment,
            phase: "completed",
            completed_at: new Date().toISOString(),
            assets: [asset],
            findings: [...findings],
            metrics,
          };

          const report = defaultReportGenerator.generate({
            assessment: completedAssessment,
            format: options.format as ReportFormat,
          });

          if (options.output) {
            const outPath = absoluteCallerPath(options.output);
            await writeFile(outPath, report, "utf8");
            return {
              status: "COMPLETED",
              assessment_id: completedAssessment.assessment_id,
              target: targetPath,
              metrics,
              findings_count: findings.length,
              report_written_to: outPath,
              format: options.format,
            };
          }

          return {
            status: "COMPLETED",
            assessment_id: completedAssessment.assessment_id,
            target: targetPath,
            metrics,
            findings_count: findings.length,
            format: options.format,
            report,
          };
        }),
      ),
  });

  // 2. rea security-cvss
  cli.command(CLI_COMMANDS.securityCvss, {
    description:
      "Calculate CVSS v3.1 base score, qualitative severity, and subscores from a vector string",
    args: z.object({
      vector: z
        .string()
        .describe("CVSS v3.1 vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"),
    }),
    run: ({ args }) =>
      logCliCommand(logger, CLI_COMMANDS.securityCvss, async () => {
        const result = calculateCvss31FromVector(args.vector);
        if (!result.ok) {
          return {
            status: "ERROR",
            error: result.error,
          };
        }
        return {
          status: "SUCCESS",
          vector: result.value.vector_string,
          score: result.value.score,
          severity: result.value.severity,
          exploitability_subscore: result.value.exploitability_subscore,
          impact_subscore: result.value.impact_subscore,
        };
      }),
  });

  // 3. rea security-report
  cli.command(CLI_COMMANDS.securityReport, {
    description:
      "Generate a formatted report from an existing JSON assessment state file",
    args: z.object({
      path: z
        .string()
        .describe("Path to an exported assessment JSON state file"),
    }),
    options: z.object({
      format: z
        .enum(["markdown", "json", "sarif", "html"])
        .default("markdown")
        .describe("Target report format"),
      output: z
        .string()
        .optional()
        .describe("Optional destination file path"),
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.securityReport, async () => {
        const filePath = absoluteCallerPath(args.path);
        const content = await readFile(filePath, "utf8");
        const parsedJson = JSON.parse(content);
        const assessment = assessmentStateSchema.parse(parsedJson);

        const report = defaultReportGenerator.generate({
          assessment,
          format: options.format as ReportFormat,
        });

        if (options.output) {
          const outPath = absoluteCallerPath(options.output);
          await writeFile(outPath, report, "utf8");
          return {
            status: "SUCCESS",
            assessment_id: assessment.assessment_id,
            format: options.format,
            written_to: outPath,
          };
        }

        return {
          status: "SUCCESS",
          assessment_id: assessment.assessment_id,
          format: options.format,
          report,
        };
      }),
  });
};
