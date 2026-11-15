import { open, stat } from "node:fs/promises";
import { basename } from "node:path";
import type { Logger } from "pino";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import {
  calculateCvssSchema,
  deepFirmwareInspectionSchema,
  deviceInspectionSchema,
  embeddedOsAuditSchema,
  generateSecurityReportSchema,
  runMultiAgentAssessmentSchema,
  scanSecurityTargetSchema,
} from "../contracts/securitySchemas.js";
import {
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
import { ChiefSecurityOrchestrator } from "../security/agents/orchestrator.js";
import { VulnerabilityEngine } from "../security/engines/vulnerability/engine.js";
import { defaultFirmwareDeepAnalyzer } from "../security/firmware/firmwareDeepAnalyzer.js";
import { defaultDeviceInterfaceAnalyzer } from "../security/device/deviceInterfaceAnalyzer.js";
import { defaultEmbeddedOsAnalyzer } from "../security/os/embeddedOsAnalyzer.js";
import {
  defaultReportGenerator,
  type ReportFormat,
} from "../security/reporting/reportGenerator.js";

/**
 * Register cybersecurity MCP tools on EvidenceMcpServer:
 * - security_scan: Rapid vulnerability discovery across tools.
 * - security_cvss: Standard CVSS v3.1 calculator and metric decoder.
 * - security_report: Multi-format explainable reporting engine.
 * - security_multiagent_assess: Full multi-agent security assessment.
 * - security_firmware_inspect: Deep firmware partition and secret audit.
 * - security_device_inspect: Physical and logical device interface security audit (UART, ADB, JTAG).
 * - security_os_audit: Embedded operating system, credentials, and kernel security audit.
 */
export const registerSecurityTools = (
  server: EvidenceMcpServer,
  logger: Logger,
): void => {
  const vulnEngine = new VulnerabilityEngine();
  const orchestrator = new ChiefSecurityOrchestrator();

  // 1. security_scan
  server.registerTool(
    "security_scan",
    {
      description:
        "Perform vulnerability discovery and security posture evaluation on an authorized target using static and signature analysis tools.",
      inputSchema: scanSecurityTargetSchema,
    },
    async (input) => {
      logger.info({ path: input.path }, "MCP tool security_scan invoked");

      try {
        const targetStats = await stat(input.path);
        let assetType: AssetType = "source_repository";
        if (targetStats.isFile()) {
          const lower = input.path.toLowerCase();
          if (
            lower.endsWith(".bin") ||
            lower.endsWith(".img") ||
            lower.endsWith(".rom") ||
            lower.endsWith(".fw") ||
            lower.endsWith(".squashfs")
          ) {
            assetType = "firmware_image";
          } else {
            // Check for SquashFS magic without relying purely on extensions
            let isSquash = false;
            let handle;
            try {
              handle = await open(input.path, "r");
              const magicBuf = Buffer.alloc(4);
              await handle.read(magicBuf, 0, 4, 0);
              await handle.close();
              const magic4 = magicBuf.toString("utf8");
              if (magic4 === "sqsh" || magic4 === "hsqs") {
                isSquash = true;
              }
            } catch {
              if (handle) {
                try {
                  await handle.close();
                } catch {
                  // ignore
                }
              }
            }
            assetType = isSquash ? "firmware_image" : "compiled_binary";
          }
        }

        const assetName = basename(input.path);
        const assetId = computeAssetId({
          name: assetName,
          type: assetType,
        });

        const asset: AssetRecord = {
          id: assetId,
          name: assetName,
          type: assetType,
          path: input.path,
          digest: null,
          architecture: null,
          version: null,
          environment: null,
          tags: ["mcp-target"],
          metadata: {
            is_directory: targetStats.isDirectory(),
          },
        };

        const scope = {
          allowed_targets: [input.path],
          denied_targets: [],
          authorized_by: input.authorized_by,
          authorization_reference: input.authorization_reference,
          valid_until: new Date(Date.now() + 86_400_000).toISOString(),
          allow_active_verification: false,
        };

        const initialAssessment = createAssessmentState({
          objective: {
            title: `Security Scan of ${assetName}`,
            target_technologies: [],
            compliance_frameworks: [],
            focus_areas: ["Vulnerability Discovery"],
            depth: input.depth as AssessmentDepth,
          },
          scope,
        });

        const discovery = await vulnEngine.discover({
          asset,
          scope,
        });

        if (!discovery.ok) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    status: "FAILED",
                    error: discovery.error,
                  },
                  null,
                  2,
                ),
              },
            ],
            isError: true,
          };
        }

        const metrics = calculateAssessmentMetrics(
          [asset],
          discovery.value.findings,
        );

        const completedAssessment: AssessmentState = {
          ...initialAssessment,
          phase: "completed",
          completed_at: new Date().toISOString(),
          assets: [asset],
          findings: [...discovery.value.findings],
          metrics,
        };

        const scanMeta = {
          status: discovery.value.status,
          selected_scanners: discovery.value.selected_scanners,
          executed_scanners: discovery.value.executed_scanners,
          completed_scanners: discovery.value.completed_scanners,
          failed_scanners: discovery.value.failed_scanners,
          skipped_scanners: discovery.value.skipped_scanners,
          scanner_warnings: discovery.value.scanner_warnings,
          unsupported_input_types: [],
          coverage: {
            discovered_files: 1,
            extracted_files: 0,
            eligible_binaries: assetType === "compiled_binary" ? 1 : 0,
            binaries_analyzed:
              discovery.value.executed_scanners.length > 0 &&
              assetType === "compiled_binary"
                ? 1
                : 0,
            binaries_partially_analyzed: 0,
            binaries_skipped_or_failed:
              discovery.value.status === "NOT_SCANNED" &&
              assetType === "compiled_binary"
                ? 1
                : 0,
          },
        };

        const report = defaultReportGenerator.generate({
          assessment: completedAssessment,
          format: input.format as ReportFormat,
          scanExecution: scanMeta,
        });

        return {
          content: [
            {
              type: "text",
              text: report,
            },
          ],
        };
      } catch (e: unknown) {
        return {
          content: [
            {
              type: "text",
              text: `Security scan error: ${e instanceof Error ? e.message : String(e)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  // 2. security_cvss
  server.registerTool(
    "security_cvss",
    {
      description:
        "Calculate CVSS v3.1 base score, qualitative severity, and subscores from a standard vector string.",
      inputSchema: calculateCvssSchema,
    },
    async (input) => {
      const calcResult = calculateCvss31FromVector(input.vector_string);
      if (!calcResult.ok) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                { status: "ERROR", error: calcResult.error },
                null,
                2,
              ),
            },
          ],
          isError: true,
        };
      }

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(calcResult.value, null, 2),
          },
        ],
      };
    },
  );

  // 3. security_report
  server.registerTool(
    "security_report",
    {
      description:
        "Generate a formatted explainable security report in Markdown, JSON, SARIF v2.1.0, or self-contained HTML.",
      inputSchema: generateSecurityReportSchema,
    },
    async (input) => {
      // In-memory dummy state when state is requested by ID
      const state: AssessmentState = createAssessmentState({
        objective: {
          title: `Security Report for ${input.assessment_id}`,
          target_technologies: [],
          compliance_frameworks: [],
          focus_areas: [],
          depth: "standard",
        },
        scope: {
          allowed_targets: ["/target"],
          denied_targets: [],
          authorized_by: "MCP",
          authorization_reference: "REF",
          valid_until: new Date(Date.now() + 86_400_000).toISOString(),
          allow_active_verification: false,
        },
      });

      const report = defaultReportGenerator.generate({
        assessment: state,
        format: input.format as ReportFormat,
      });

      return {
        content: [
          {
            type: "text",
            text: report,
          },
        ],
      };
    },
  );

  // 4. security_multiagent_assess
  server.registerTool(
    "security_multiagent_assess",
    {
      description:
        "Execute end-to-end multi-agent cybersecurity team assessment across all asset classes (software, binaries, firmware, and device interfaces).",
      inputSchema: runMultiAgentAssessmentSchema,
    },
    async (input) => {
      logger.info(
        { path: input.target_path },
        "MCP tool security_multiagent_assess invoked",
      );

      const scope = {
        allowed_targets: [input.target_path],
        denied_targets: [],
        authorized_by: input.authorized_by,
        authorization_reference: input.authorization_reference,
        valid_until: new Date(Date.now() + 86_400_000).toISOString(),
        allow_active_verification: false,
      };

      const initialState = createAssessmentState({
        objective: {
          title: input.title,
          target_technologies: [],
          compliance_frameworks: ["OWASP Top 10", "CWE Top 25"],
          focus_areas: ["Full-Stack Multi-Agent Security Audit"],
          depth: input.depth as AssessmentDepth,
        },
        scope,
      });

      const assessmentResult = await orchestrator.runAssessment(initialState);
      if (!assessmentResult.ok) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "FAILED",
                  error: assessmentResult.error,
                },
                null,
                2,
              ),
            },
          ],
          isError: true,
        };
      }

      const report = defaultReportGenerator.generate({
        assessment: assessmentResult.value.assessment,
        format: input.format as ReportFormat,
      });

      return {
        content: [
          {
            type: "text",
            text: report,
          },
        ],
      };
    },
  );

  // 5. security_firmware_inspect
  server.registerTool(
    "security_firmware_inspect",
    {
      description:
        "Perform deep firmware security analysis including architecture identification, embedded secret discovery, shadow hash auditing, and bootloader security.",
      inputSchema: deepFirmwareInspectionSchema,
    },
    async (input) => {
      const result = await defaultFirmwareDeepAnalyzer.analyze(input.path);
      if (!result.ok) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                { status: "ERROR", error: result.error },
                null,
                2,
              ),
            },
          ],
          isError: true,
        };
      }

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result.value, null, 2),
          },
        ],
      };
    },
  );

  // 6. security_device_inspect
  server.registerTool(
    "security_device_inspect",
    {
      description:
        "Inspect physical and logical device communication interfaces (UART serial consoles, ADB, JTAG/SWD, USB) for unauthenticated root shells, exposed debug ports, and security weaknesses.",
      inputSchema: deviceInspectionSchema,
    },
    async (input) => {
      const result = await defaultDeviceInterfaceAnalyzer.analyze({
        target: input.target,
        ...(input.interface_type !== undefined
          ? { interface_type: input.interface_type }
          : {}),
      });

      if (!result.ok) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                { status: "ERROR", error: result.error.message },
                null,
                2,
              ),
            },
          ],
          isError: true,
        };
      }

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result.value, null, 2),
          },
        ],
      };
    },
  );

  // 7. security_os_audit
  server.registerTool(
    "security_os_audit",
    {
      description:
        "Audit extracted embedded operating system filesystems, /etc/shadow credentials, SUID binaries, and Linux kernel configurations for vulnerabilities.",
      inputSchema: embeddedOsAuditSchema,
    },
    async (input) => {
      const result = await defaultEmbeddedOsAnalyzer.analyze(input.path);
      if (!result.ok) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                { status: "ERROR", error: result.error.message },
                null,
                2,
              ),
            },
          ],
          isError: true,
        };
      }

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result.value, null, 2),
          },
        ],
      };
    },
  );
};
