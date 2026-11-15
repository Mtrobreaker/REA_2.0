import { existsSync } from "node:fs";
import { access, constants, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { z } from "incur";
import type { Logger } from "pino";
import { SecurityAssessmentService } from "../application/security/assessment/SecurityAssessmentService.js";
import { SarifExporter } from "../application/security/reporting/SarifExporter.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import {
  assessmentIdSchema,
  assessmentStateSchema,
  type AssessmentDepth,
  type AssessmentId,
} from "../domain/security/assessment.js";
import { calculateCvss31FromVector } from "../domain/security/cvssCalculator.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import {
  defaultReportGenerator,
  type ReportFormat,
  type ScanExecutionMetadata,
} from "../security/reporting/reportGenerator.js";
import { withCommandCancellation } from "./commandCancellation.js";
import type { CliInstance } from "./types.js";

/**
 * Register cybersecurity CLI commands (M1.1B — Connected to shared SecurityAssessmentService):
 * - rea security-scan <target> [--format=markdown|json|sarif|html] [--output=<file>] [--db-path=<file>]
 * - rea security-cvss <vector>
 * - rea security-report <assessment-id-or-file> [--format=markdown|json|sarif|html] [--output=<file>] [--db-path=<file>]
 */
export const registerSecurityCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<Record<string, string | undefined>>,
): void => {
  const resolveDbPath = (
    explicitDbPath?: string | undefined,
  ): string | undefined =>
    explicitDbPath ??
    environment.REA_SECURITY_DB_PATH ??
    process.env.REA_SECURITY_DB_PATH;

  // 1. rea security-scan
  cli.command(CLI_COMMANDS.securityScan, {
    description:
      "Perform end-to-end security assessment on an authorized firmware image, ELF binary, or repository via SecurityAssessmentService",
    args: z.object({
      path: z
        .string()
        .describe(
          "Target firmware image, ELF binary, or directory path to inspect and assess",
        ),
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
      maxBinaries: z
        .number()
        .int()
        .positive()
        .optional()
        .describe(
          "Maximum ELF binaries to analyze in bounded worker queue (default: 15)",
        ),
      dbPath: z
        .string()
        .optional()
        .describe("Optional SQLite blackboard database path"),
      allowedRoot: z
        .string()
        .optional()
        .describe("Optional authorized workspace root boundary"),
      deniedTargets: z
        .array(z.string())
        .optional()
        .describe("Optional list of explicitly denied target paths"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) =>
        logCliCommand(logger, CLI_COMMANDS.securityScan, async () => {
          const rawPath = args.path?.trim() ?? "";
          if (!rawPath || rawPath.includes("\0")) {
            return {
              status: "FAILED",
              error_code: "INVALID_TARGET",
              error: "Target path must be a non-empty valid filesystem path.",
            };
          }

          // Reject explicit relative parent-traversal escapes when allowedRoot is not explicitly overriding
          const segments = rawPath.split(/[\\/]+/);
          if (segments.includes("..")) {
            return {
              status: "FAILED",
              error_code: "AUTHORIZATION_DENIED",
              error: `Path traversal segment ('..') is not permitted in CLI target path '${rawPath}'.`,
            };
          }

          const targetPath = absoluteCallerPath(rawPath);
          const dbPath = resolveDbPath(
            options.dbPath ? absoluteCallerPath(options.dbPath) : undefined,
          );
          const allowedTargets = options.allowedRoot
            ? [
                options.allowedRoot.includes("..")
                  ? options.allowedRoot
                  : absoluteCallerPath(options.allowedRoot),
              ]
            : undefined;
          const deniedTargets = options.deniedTargets?.map((t) =>
            t.includes("..") ? t : absoluteCallerPath(t),
          );

          const service = new SecurityAssessmentService({
            dbPath,
          });

          const assessmentResult = await service.runAssessment({
            targetPath,
            allowedTargets,
            deniedTargets,
            authorizedBy: options.authorizedBy,
            authorizationReference: options.reference,
            depth: options.depth as AssessmentDepth,
            format: options.format as ReportFormat,
            maxBinariesToAnalyze: options.maxBinaries,
            signal,
          });

          if (!assessmentResult.ok) {
            return {
              status: "FAILED",
              error_code: assessmentResult.error.code,
              error: assessmentResult.error.message,
            };
          }

          const out = assessmentResult.value;
          const rootAsset = out.assessment.assets[0];
          const rootSha256 =
            out.extractionSummary?.rootFirmwareSha256 ??
            rootAsset?.digest?.sha256 ??
            null;

          if (options.output) {
            const outPath = absoluteCallerPath(options.output);
            await writeFile(outPath, out.report, "utf8");
            return {
              status: out.status,
              assessment_id: out.assessmentId,
              target: targetPath,
              sha256: rootSha256,
              metrics: out.assessment.metrics,
              findings_count: out.assessment.findings.length,
              verified_findings_count: out.assessment.metrics.verified_findings,
              scan_execution: out.scanExecution,
              extraction_summary: out.extractionSummary ?? null,
              binary_metrics: out.binaryMetrics,
              stage_timings_ms: out.stageTimingsMs,
              report_written_to: outPath,
              format: options.format,
            };
          }

          return {
            status: out.status,
            assessment_id: out.assessmentId,
            target: targetPath,
            sha256: rootSha256,
            metrics: out.assessment.metrics,
            findings_count: out.assessment.findings.length,
            verified_findings_count: out.assessment.metrics.verified_findings,
            scan_execution: out.scanExecution,
            extraction_summary: out.extractionSummary ?? null,
            binary_metrics: out.binaryMetrics,
            stage_timings_ms: out.stageTimingsMs,
            format: options.format,
            report: out.report,
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
        .describe(
          "CVSS v3.1 vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
        ),
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
      "Generate a formatted report from a persisted SQLite assessment ID (asm_<64hex>) or an exported JSON assessment state file",
    args: z.object({
      path: z
        .string()
        .describe(
          "Persisted assessment ID (asm_<64hex>) or path to an exported assessment JSON state file",
        ),
    }),
    options: z.object({
      format: z
        .enum(["markdown", "json", "sarif", "html"])
        .default("markdown")
        .describe("Target report format"),
      output: z.string().optional().describe("Optional destination file path"),
      dbPath: z
        .string()
        .optional()
        .describe("Optional SQLite blackboard database path"),
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.securityReport, async () => {
        const rawInput = args.path?.trim() ?? "";
        if (!rawInput || rawInput.includes("\0")) {
          return {
            status: "FAILED",
            error_code: "INVALID_TARGET",
            error: "Assessment ID or report state path must be non-empty.",
          };
        }

        const format = (options.format ?? "markdown") as ReportFormat;
        const looksLikeFilePath =
          rawInput.endsWith(".json") ||
          rawInput.includes("/") ||
          rawInput.includes("\\");

        // Route 1: Persisted Assessment ID (or non-path identifier) via SecurityAssessmentService
        if (!looksLikeFilePath || rawInput.startsWith("asm_")) {
          const parsedId = assessmentIdSchema.safeParse(rawInput);
          if (!parsedId.success) {
            return {
              status: "FAILED",
              error_code: "INVALID_TARGET",
              error: `Invalid assessment ID '${rawInput}': must match asm_<64 lowercase hex characters>.`,
            };
          }

          const dbPath = resolveDbPath(
            options.dbPath ? absoluteCallerPath(options.dbPath) : undefined,
          );
          const service = new SecurityAssessmentService({
            dbPath,
          });

          const persistedRes = await service.generateReportFromPersisted(
            parsedId.data as AssessmentId,
            format,
          );
          if (!persistedRes.ok) {
            return {
              status: "FAILED",
              error_code: persistedRes.error.code,
              error: persistedRes.error.message,
            };
          }

          const persisted = persistedRes.value;
          if (options.output) {
            const outPath = absoluteCallerPath(options.output);
            await writeFile(outPath, persisted.report, "utf8");
            return {
              status: "SUCCESS",
              assessment_status: persisted.status,
              assessment_id: persisted.assessmentId,
              format,
              metrics: persisted.assessment.metrics,
              findings_count: persisted.assessment.findings.length,
              verified_findings_count:
                persisted.assessment.metrics.verified_findings,
              scan_execution: persisted.scanExecution,
              extraction_summary: persisted.extractionSummary ?? null,
              binary_metrics: persisted.binaryMetrics,
              written_to: outPath,
            };
          }

          return {
            status: "SUCCESS",
            assessment_status: persisted.status,
            assessment_id: persisted.assessmentId,
            format,
            metrics: persisted.assessment.metrics,
            findings_count: persisted.assessment.findings.length,
            verified_findings_count:
              persisted.assessment.metrics.verified_findings,
            scan_execution: persisted.scanExecution,
            extraction_summary: persisted.extractionSummary ?? null,
            binary_metrics: persisted.binaryMetrics,
            report: persisted.report,
          };
        }

        // Route 2: Exported JSON state file on disk (validated fail-closed, never returns dummy data)
        const filePath = resolve(absoluteCallerPath(rawInput));
        if (!existsSync(filePath)) {
          return {
            status: "FAILED",
            error_code: "ASSESSMENT_NOT_FOUND",
            error: `Assessment state file '${filePath}' does not exist.`,
          };
        }

        try {
          await access(filePath, constants.R_OK);
        } catch (cause) {
          return {
            status: "FAILED",
            error_code: "AUTHORIZATION_DENIED",
            error: `Insufficient permissions to read assessment file '${filePath}': ${cause instanceof Error ? cause.message : String(cause)}`,
          };
        }

        let parsedJson: unknown;
        try {
          const content = await readFile(filePath, "utf8");
          parsedJson = JSON.parse(content);
        } catch (cause) {
          return {
            status: "FAILED",
            error_code: "STORAGE_ERROR",
            error: `Corrupted or unreadable JSON assessment file '${filePath}': ${cause instanceof Error ? cause.message : String(cause)}`,
          };
        }

        const parsedState = assessmentStateSchema.safeParse(parsedJson);
        if (!parsedState.success) {
          return {
            status: "FAILED",
            error_code: "STORAGE_ERROR",
            error: `Invalid or corrupted assessment state schema in '${filePath}': ${parsedState.error.message}`,
          };
        }

        const assessment = parsedState.data;
        const embeddedScanExec = (
          parsedJson as { scan_execution?: ScanExecutionMetadata }
        )?.scan_execution;
        const report =
          format === "sarif"
            ? JSON.stringify(
                SarifExporter.exportFindings(assessment.findings, {
                  assessmentId: assessment.assessment_id,
                }),
                null,
                2,
              )
            : defaultReportGenerator.generate({
                assessment,
                format,
                ...(embeddedScanExec !== undefined
                  ? { scanExecution: embeddedScanExec }
                  : {}),
              });

        if (options.output) {
          const outPath = absoluteCallerPath(options.output);
          await writeFile(outPath, report, "utf8");
          return {
            status: "SUCCESS",
            assessment_status:
              embeddedScanExec?.status ??
              (assessment.phase === "completed" ? "COMPLETED" : "FAILED"),
            assessment_id: assessment.assessment_id,
            format,
            written_to: outPath,
          };
        }

        return {
          status: "SUCCESS",
          assessment_status:
            embeddedScanExec?.status ??
            (assessment.phase === "completed" ? "COMPLETED" : "FAILED"),
          assessment_id: assessment.assessment_id,
          format,
          report,
        };
      }),
  });
};
