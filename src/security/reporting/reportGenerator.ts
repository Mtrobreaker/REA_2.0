import type { AssessmentState } from "../../domain/security/assessment.js";
import type {
  FindingLocation,
  SecurityFinding,
} from "../../domain/security/finding.js";
import { SecurityKnowledgeGraph } from "../graph/knowledgeGraph.js";

export type ReportFormat = "markdown" | "json" | "sarif" | "html";

export interface ScanExecutionMetadata {
  readonly status:
    | "NOT_SCANNED"
    | "RUNNING"
    | "COMPLETED"
    | "PARTIAL"
    | "FAILED";
  readonly selected_scanners: readonly string[];
  readonly executed_scanners: readonly string[];
  readonly completed_scanners: readonly string[];
  readonly failed_scanners: readonly string[];
  readonly skipped_scanners: readonly string[];
  readonly scanner_warnings: readonly string[];
  readonly unsupported_input_types: readonly string[];
  readonly extraction_gaps?: readonly {
    readonly path: string;
    readonly reason: string;
  }[];
  readonly coverage: {
    readonly discovered_files: number;
    readonly extracted_files: number;
    readonly eligible_binaries: number;
    readonly binaries_analyzed: number;
    readonly binaries_partially_analyzed: number;
    readonly binaries_skipped_or_failed: number;
  };
}

export interface GenerateReportOptions {
  readonly assessment: AssessmentState;
  readonly format?: ReportFormat;
  readonly title?: string;
  readonly scanExecution?: ScanExecutionMetadata | undefined;
}

/**
 * Universal Security Assessment Reporting Engine.
 * Supports Markdown, JSON, SARIF v2.1.0, and self-contained interactive HTML formats.
 */
export class SecurityReportGenerator {
  /**
   * Primary entrypoint to generate an assessment report in the desired format.
   */
  public generate(options: GenerateReportOptions): string {
    const format = options.format ?? "markdown";
    switch (format) {
      case "markdown":
        return this.generateMarkdown(
          options.assessment,
          options.title,
          options.scanExecution,
        );
      case "json":
        return this.generateJson(options.assessment, options.scanExecution);
      case "sarif":
        return this.generateSarif(options.assessment);
      case "html":
        return this.generateHtml(options.assessment, options.title);
      default:
        throw new Error(`Unsupported report format: ${String(format)}`);
    }
  }

  /**
   * Generate an exhaustive, explainable Markdown report.
   */
  public generateMarkdown(
    assessment: AssessmentState,
    customTitle?: string,
    scanExecution?: ScanExecutionMetadata,
  ): string {
    const title = customTitle ?? assessment.objective.title;
    const lines: string[] = [];

    lines.push(`# Security Assessment Report: ${title}`);
    lines.push("");
    lines.push(`**Assessment ID:** \`${assessment.assessment_id}\`  `);
    lines.push(`**Phase:** \`${assessment.phase.toUpperCase()}\`  `);
    if (scanExecution) {
      lines.push(`**Scan Execution Status:** \`${scanExecution.status}\`  `);
    }
    lines.push(`**Created:** ${assessment.created_at}  `);
    lines.push(`**Completed:** ${assessment.completed_at ?? "In Progress"}  `);
    lines.push(
      `**Authorized By:** ${assessment.scope.authorized_by} (Ref: \`${assessment.scope.authorization_reference}\`)  `,
    );
    lines.push("");

    // 1. Executive Summary
    lines.push("## 1. Executive Summary");
    lines.push("");
    lines.push(
      `This security assessment was conducted against authorized targets with a **${assessment.objective.depth}** inspection depth. ` +
        `A total of **${assessment.findings.length}** security finding(s) were identified across **${assessment.assets.length}** evaluated asset(s).`,
    );
    lines.push("");
    if (
      scanExecution &&
      (scanExecution.status === "PARTIAL" ||
        scanExecution.status === "NOT_SCANNED")
    ) {
      lines.push(
        `> **⚠️ ${scanExecution.status} Analysis Coverage Notice:** This assessment completed with status \`${scanExecution.status}\` ` +
          `(${scanExecution.coverage.binaries_analyzed} of ${scanExecution.coverage.eligible_binaries} eligible ELF binaries analyzed; ` +
          `${scanExecution.coverage.binaries_skipped_or_failed} binaries skipped or unanalyzed). ` +
          `Partial or unexecuted analysis must NEVER be interpreted as a clean or vulnerability-free posture.`,
      );
      lines.push("");
    }

    // Metrics Dashboard Table
    lines.push("### Security Posture Metrics");
    lines.push("");
    lines.push("| Severity | Count | Verified | Inferred / Unknown |");
    lines.push("| :--- | :--- | :--- | :--- |");
    lines.push(
      `| 🔴 **CRITICAL** | ${assessment.metrics.critical_findings} | ${this.countVerified(assessment.findings, "CRITICAL")} | ${this.countUnverified(assessment.findings, "CRITICAL")} |`,
    );
    lines.push(
      `| 🟠 **HIGH** | ${assessment.metrics.high_findings} | ${this.countVerified(assessment.findings, "HIGH")} | ${this.countUnverified(assessment.findings, "HIGH")} |`,
    );
    lines.push(
      `| 🟡 **MEDIUM** | ${assessment.metrics.medium_findings} | ${this.countVerified(assessment.findings, "MEDIUM")} | ${this.countUnverified(assessment.findings, "MEDIUM")} |`,
    );
    lines.push(
      `| 🔵 **LOW** | ${assessment.metrics.low_findings} | ${this.countVerified(assessment.findings, "LOW")} | ${this.countUnverified(assessment.findings, "LOW")} |`,
    );
    lines.push(
      `| ⚪ **INFORMATIONAL** | ${assessment.metrics.info_findings} | ${this.countVerified(assessment.findings, "INFORMATIONAL")} | ${this.countUnverified(assessment.findings, "INFORMATIONAL")} |`,
    );
    lines.push(
      `| **TOTAL** | **${assessment.metrics.total_findings}** | **${assessment.metrics.verified_findings}** | **${assessment.metrics.total_findings - assessment.metrics.verified_findings}** |`,
    );
    lines.push("");

    // 2. Scope & Boundaries
    lines.push("## 2. Assessment Scope & Target Authorization");
    lines.push("");
    lines.push("- **Allowed Targets:**");
    for (const t of assessment.scope.allowed_targets) {
      lines.push(`  - \`${t}\``);
    }
    if (assessment.scope.denied_targets.length > 0) {
      lines.push("- **Explicitly Excluded Targets:**");
      for (const t of assessment.scope.denied_targets) {
        lines.push(`  - \`${t}\``);
      }
    }
    lines.push(
      `- **Active Verification Allowed:** \`${assessment.scope.allow_active_verification}\``,
    );
    lines.push(`- **Scope Valid Until:** \`${assessment.scope.valid_until}\``);
    lines.push("");

    // 2.1. Scan Execution & Truthful Coverage
    if (scanExecution) {
      lines.push("## 2.1. Scan Execution & Truthful Coverage");
      lines.push("");
      lines.push(`- **Scan Status:** \`${scanExecution.status}\``);
      lines.push(
        `- **Selected Scanners:** ${scanExecution.selected_scanners.length > 0 ? scanExecution.selected_scanners.map((s) => `\`${s}\``).join(", ") : "*None*"}`,
      );
      lines.push(
        `- **Actually Executed Scanners:** ${scanExecution.executed_scanners.length > 0 ? scanExecution.executed_scanners.map((s) => `\`${s}\``).join(", ") : "*None*"}`,
      );
      lines.push(
        `- **Successfully Completed Scanners:** ${scanExecution.completed_scanners.length > 0 ? scanExecution.completed_scanners.map((s) => `\`${s}\``).join(", ") : "*None*"}`,
      );
      lines.push(
        `- **Failed Scanners:** ${scanExecution.failed_scanners.length > 0 ? scanExecution.failed_scanners.map((s) => `\`${s}\``).join(", ") : "*None*"}`,
      );
      lines.push(
        `- **Skipped Scanners:** ${scanExecution.skipped_scanners.length > 0 ? scanExecution.skipped_scanners.map((s) => `\`${s}\``).join(", ") : "*None*"}`,
      );
      lines.push(
        `- **Scanner Warnings:** ${scanExecution.scanner_warnings.length > 0 ? scanExecution.scanner_warnings.join("; ") : "*None*"}`,
      );
      lines.push(
        `- **Unsupported Input Types:** ${scanExecution.unsupported_input_types.length > 0 ? scanExecution.unsupported_input_types.join(", ") : "*None*"}`,
      );
      if (
        scanExecution.extraction_gaps &&
        scanExecution.extraction_gaps.length > 0
      ) {
        lines.push("- **Extraction Gaps:**");
        for (const gap of scanExecution.extraction_gaps) {
          lines.push(`  - \`${gap.path}\`: ${gap.reason}`);
        }
      }
      lines.push("- **File & Binary Analysis Coverage:**");
      lines.push(
        `  - Discovered files: **${scanExecution.coverage.discovered_files}**`,
      );
      lines.push(
        `  - Extracted files: **${scanExecution.coverage.extracted_files}**`,
      );
      lines.push(
        `  - Eligible binaries: **${scanExecution.coverage.eligible_binaries}**`,
      );
      lines.push(
        `  - Binaries analyzed: **${scanExecution.coverage.binaries_analyzed}**`,
      );
      lines.push(
        `  - Binaries partially analyzed: **${scanExecution.coverage.binaries_partially_analyzed}**`,
      );
      lines.push(
        `  - Binaries skipped or failed: **${scanExecution.coverage.binaries_skipped_or_failed}**`,
      );
      lines.push("");
    }

    // 3. Evaluated Assets
    lines.push("## 3. Evaluated Assets");
    lines.push("");
    if (assessment.assets.length === 0) {
      lines.push("*No distinct asset records registered.*");
    } else {
      lines.push("| Asset Name | Type | Path / URI | Architecture |");
      lines.push("| :--- | :--- | :--- | :--- |");
      for (const a of assessment.assets) {
        lines.push(
          `| **${a.name}** | \`${a.type}\` | \`${a.path ?? "N/A"}\` | \`${a.architecture ?? "N/A"}\` |`,
        );
      }

      const analyzedBinaries = assessment.assets.filter(
        (a) =>
          a.type === "compiled_binary" &&
          a.metadata?.lifecycle_state === "analyzed",
      );
      const skippedBinaries = assessment.assets.filter(
        (a) =>
          a.type === "compiled_binary" &&
          (a.metadata?.lifecycle_state === "skipped_budget" ||
            a.metadata?.lifecycle_state === "failed" ||
            a.metadata?.skipped === true),
      );

      if (analyzedBinaries.length > 0 || skippedBinaries.length > 0) {
        lines.push("");
        lines.push("### 3.1. ELF Binary Analysis & Skipped Binary Inventory");
        lines.push("");
        lines.push(
          `- **Analyzed ELF Binaries (${analyzedBinaries.length}):** ` +
            (analyzedBinaries.length > 0
              ? analyzedBinaries
                  .map(
                    (b) =>
                      `\`${String(b.metadata?.relativePath ?? b.path ?? b.name)}\``,
                  )
                  .join(", ")
              : "*None*"),
        );
        lines.push(
          `- **Skipped / Unanalyzed ELF Binaries (${skippedBinaries.length}):**`,
        );
        if (skippedBinaries.length === 0) {
          lines.push("  - *None*");
        } else {
          for (const sb of skippedBinaries) {
            const rel = String(sb.metadata?.relativePath ?? sb.path ?? sb.name);
            const reason = String(
              sb.metadata?.skipped_reason ??
                sb.metadata?.error ??
                "Skipped due to task budget",
            );
            lines.push(
              `  - \`${rel}\` (\`${sb.architecture ?? "unknown"}\`): ${reason}`,
            );
          }
        }
      }
    }
    lines.push("");

    // 4. Detailed Explainable Security Findings
    lines.push("## 4. Security Findings & Technical Dossiers");
    lines.push("");

    if (assessment.findings.length === 0) {
      if (scanExecution?.status === "NOT_SCANNED") {
        lines.push(
          "*NOT_SCANNED: No security scanners were executed against the target.*",
        );
      } else if (scanExecution?.status === "PARTIAL") {
        lines.push(
          `*No findings detected within partial analysis coverage (${scanExecution.completed_scanners.join(", ") || "partial"}). Unanalyzed areas remain unexamined.*`,
        );
      } else {
        lines.push(
          "*No security vulnerabilities or weaknesses detected within the stated coverage. Note: Absence of findings within stated coverage does not imply the target is vulnerability-free.*",
        );
      }
    } else {
      // Sort findings by severity priority
      const sorted = [...assessment.findings].sort(this.compareFindingSeverity);

      for (let i = 0; i < sorted.length; i++) {
        const f = sorted[i]!;
        const sevBadge = this.formatSeverityBadge(f.severity.level);

        lines.push(`### 4.${i + 1}. [${sevBadge}] ${f.name}`);
        lines.push("");
        lines.push(`- **Finding ID:** \`${f.id}\``);
        lines.push(
          `- **Affected Asset:** \`${f.affected_asset.name}\` (${f.affected_asset.type})`,
        );
        lines.push(`- **Location:** ${this.formatLocation(f.location)}`);
        lines.push(
          `- **CVSS v3.1:** **${f.severity.cvss_score ?? "N/A"}** (\`${f.severity.cvss_vector ?? "N/A"}\`)`,
        );
        lines.push(
          `- **Verification Status:** \`${f.verification_status}\` (Confidence: \`${f.confidence.level}\`)`,
        );
        lines.push(`- **Remediation Priority:** \`${f.remediation.priority}\``);

        // Classification
        const classParts: string[] = [];
        if (f.classification.cve.length > 0) {
          classParts.push(
            `CVE: ${f.classification.cve.map((c) => `\`${c}\``).join(", ")}`,
          );
        }
        if (f.classification.cwe.length > 0) {
          classParts.push(
            `CWE: ${f.classification.cwe.map((c) => `\`${c}\``).join(", ")}`,
          );
        }
        if (f.classification.mitre_attack.length > 0) {
          classParts.push(
            `ATT&CK: ${f.classification.mitre_attack.map((m) => `\`${m}\``).join(", ")}`,
          );
        }
        if (f.classification.owasp.length > 0) {
          classParts.push(
            `OWASP: ${f.classification.owasp.map((o) => `\`${o}\``).join(", ")}`,
          );
        }
        if (classParts.length > 0) {
          lines.push(`- **Classification:** ${classParts.join(" | ")}`);
        }
        lines.push("");

        // Technical Description
        lines.push("#### Technical Description");
        lines.push(f.technical_description);
        lines.push("");

        // Root Cause Analysis
        lines.push("#### Root Cause Analysis");
        lines.push(f.root_cause);
        lines.push("");

        // Impact & Exploitability
        lines.push("#### Impact & Exploitability");
        lines.push(`**Exploitability Tier:** \`${f.impact.exploitability}\`  `);
        lines.push(f.impact.description);
        if (f.impact.attack_prerequisites.length > 0) {
          lines.push("");
          lines.push("**Attack Prerequisites:**");
          for (const req of f.impact.attack_prerequisites) {
            lines.push(`- ${req}`);
          }
        }
        lines.push("");

        // Reproduction Steps
        if (f.reproduction_steps.length > 0) {
          lines.push("#### Controlled Reproduction Steps");
          for (
            let stepIdx = 0;
            stepIdx < f.reproduction_steps.length;
            stepIdx++
          ) {
            lines.push(`${stepIdx + 1}. ${f.reproduction_steps[stepIdx]}`);
          }
          lines.push("");
        }

        // Remediation Guidance & Patch
        lines.push("#### Remediation Strategy");
        lines.push(f.remediation.description);
        lines.push("");

        if (f.remediation.code_diff) {
          lines.push("```diff");
          lines.push(f.remediation.code_diff);
          lines.push("```");
          lines.push("");
        }

        if (f.remediation.config_example) {
          lines.push("```yaml");
          lines.push(f.remediation.config_example);
          lines.push("```");
          lines.push("");
        }

        if (f.remediation.validation_procedure) {
          lines.push(
            `**Validation Procedure:** ${f.remediation.validation_procedure}`,
          );
          lines.push("");
        }

        // Evidence & Provenance
        lines.push("#### Provenance & Evidence");
        lines.push(
          `- **Discovered By:** \`${f.provenance.discovered_by}\` at \`${f.provenance.discovered_at}\``,
        );
        if (f.provenance.verified_by) {
          lines.push(
            `- **Verified By:** \`${f.provenance.verified_by}\` at \`${f.provenance.verified_at}\``,
          );
        }
        if (f.evidence_ids.length > 0) {
          lines.push(
            `- **Associated Evidence IDs:** ${f.evidence_ids.map((id) => `\`${id}\``).join(", ")}`,
          );
        }
        lines.push("");
        lines.push("---");
        lines.push("");
      }
    }

    // 5. Multi-Hop Attack Path Analysis
    const graph = new SecurityKnowledgeGraph(assessment);
    const attackPaths = graph.findAttackPaths();

    lines.push("## 5. Multi-Hop Attack Path Analysis & Exploit Chaining");
    lines.push("");
    if (attackPaths.length === 0) {
      lines.push(
        "*No chained multi-hop exploit paths detected across the analyzed finding inventory.*",
      );
    } else {
      lines.push(
        `Identified **${attackPaths.length}** composite exploit chain(s) linking independent vulnerabilities:`,
      );
      lines.push("");
      for (let pIdx = 0; pIdx < attackPaths.length; pIdx++) {
        const path = attackPaths[pIdx]!;
        lines.push(
          `### 5.${pIdx + 1}. [${path.overall_severity}] ${path.title}`,
        );
        lines.push(
          `- **Cumulative Chain Risk:** **${path.cumulative_risk}/10.0**`,
        );
        lines.push(`- **Exploit Steps:**`);
        for (let sIdx = 0; sIdx < path.steps.length; sIdx++) {
          const step = path.steps[sIdx]!;
          lines.push(
            `  ${sIdx + 1}. **${step.fromNode.label}** ➔ ${step.explanation}`,
          );
        }
        lines.push(`- **Narrative:** ${path.narrative}`);
        lines.push("");
      }
    }
    lines.push("");

    // 6. Methodology & Epistemic Boundaries
    lines.push("## 6. Epistemic Boundaries & Residual Unknowns");
    lines.push("");
    lines.push(
      "REA enforces strict epistemic boundaries. Observations derived from deterministic tool execution " +
        "are treated as authoritative facts, while analytical extrapolations and AI-derived root cause models " +
        "are clearly distinguished. Any components or paths outside the explicit authorization scope remain " +
        "strictly unexamined and marked as Residual Unknowns.",
    );
    lines.push("");

    return lines.join("\n");
  }

  /**
   * Generate canonical JSON report.
   */
  public generateJson(
    assessment: AssessmentState,
    scanExecution?: ScanExecutionMetadata,
  ): string {
    if (scanExecution) {
      const analyzedBinaries = assessment.assets
        .filter(
          (a) =>
            a.type === "compiled_binary" &&
            a.metadata?.lifecycle_state === "analyzed",
        )
        .map((a) => ({
          id: a.id,
          name: a.name,
          relativePath: String(a.metadata?.relativePath ?? a.path ?? a.name),
          architecture: a.architecture,
          sha256: a.digest?.sha256 ?? null,
          partiallyAnalyzed: Boolean(a.metadata?.partially_analyzed),
        }));
      const skippedBinaries = assessment.assets
        .filter(
          (a) =>
            a.type === "compiled_binary" &&
            (a.metadata?.lifecycle_state === "skipped_budget" ||
              a.metadata?.lifecycle_state === "failed" ||
              a.metadata?.skipped === true),
        )
        .map((a) => ({
          id: a.id,
          name: a.name,
          relativePath: String(a.metadata?.relativePath ?? a.path ?? a.name),
          architecture: a.architecture,
          sha256: a.digest?.sha256 ?? null,
          lifecycleState: String(
            a.metadata?.lifecycle_state ?? "skipped_budget",
          ),
          reason: String(
            a.metadata?.skipped_reason ??
              a.metadata?.error ??
              "Skipped due to task budget",
          ),
        }));
      return JSON.stringify(
        {
          ...assessment,
          scan_status: scanExecution.status,
          scan_execution: scanExecution,
          analyzed_binaries: analyzedBinaries,
          skipped_binaries: skippedBinaries,
        },
        null,
        2,
      );
    }
    return JSON.stringify(assessment, null, 2);
  }

  /**
   * Generate SARIF v2.1.0 report for external tooling and CI/CD pipelines.
   */
  public generateSarif(assessment: AssessmentState): string {
    const rulesMap = new Map<string, any>();
    const results: any[] = [];

    for (const f of assessment.findings) {
      const ruleId =
        f.classification.cve[0] ??
        f.classification.cwe[0] ??
        f.name.replace(/\s+/g, "-");

      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, {
          id: ruleId,
          name: f.name,
          shortDescription: {
            text: f.name,
          },
          fullDescription: {
            text: f.technical_description,
          },
          help: {
            text: `${f.remediation.description}\n\nPriority: ${f.remediation.priority}`,
            markdown: `### Remediation\n${f.remediation.description}\n\n**Priority:** \`${f.remediation.priority}\``,
          },
          properties: {
            cvss_score: f.severity.cvss_score,
            cvss_vector: f.severity.cvss_vector,
            cwe: f.classification.cwe,
            cve: f.classification.cve,
            precision: f.confidence.level.toLowerCase(),
          },
        });
      }

      const sarifLevel = this.severityToSarifLevel(f.severity.level);
      const locations = [];

      if (f.location.file) {
        locations.push({
          physicalLocation: {
            artifactLocation: {
              uri: f.location.file,
            },
            region: {
              startLine: f.location.line ?? 1,
              startColumn: f.location.column ?? 1,
              endLine: f.location.end_line ?? f.location.line ?? 1,
            },
          },
          logicalLocations: f.location.function
            ? [
                {
                  name: f.location.function,
                  kind: "function",
                },
              ]
            : undefined,
        });
      }

      results.push({
        ruleId,
        level: sarifLevel,
        message: {
          text: `${f.name}: ${f.technical_description}`,
        },
        locations: locations.length > 0 ? locations : undefined,
        properties: {
          finding_id: f.id,
          verification_status: f.verification_status,
          root_cause: f.root_cause,
          impact: f.impact.description,
          exploitability: f.impact.exploitability,
          remediation_diff: f.remediation.code_diff,
        },
      });
    }

    const sarifLog = {
      $schema:
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "REA Security Platform",
              version: "1.0.0",
              informationUri: "https://github.com/rea/rea",
              rules: Array.from(rulesMap.values()),
            },
          },
          results,
        },
      ],
    };

    return JSON.stringify(sarifLog, null, 2);
  }

  /**
   * Generate a modern, self-contained interactive HTML report.
   */
  public generateHtml(
    assessment: AssessmentState,
    customTitle?: string,
  ): string {
    const title = customTitle ?? assessment.objective.title;
    const sorted = [...assessment.findings].sort(this.compareFindingSeverity);

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Assessment Report - ${this.escapeHtml(title)}</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --heading: #f0f6fc;
      --critical: #f85149;
      --high: #db6d28;
      --medium: #d29922;
      --low: #58a6ff;
      --info: #8b949e;
      --verified: #3fb950;
      --code-bg: #090c10;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header { border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }
    h1 { color: var(--heading); font-size: 2rem; margin-bottom: 0.5rem; }
    .meta { font-size: 0.9rem; color: var(--info); display: flex; flex-wrap: wrap; gap: 1.5rem; }
    .meta-item strong { color: var(--heading); }
    
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .metric-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      text-align: center;
    }
    .metric-value { font-size: 2.2rem; font-weight: 700; }
    .metric-label { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--info); }
    .val-critical { color: var(--critical); }
    .val-high { color: var(--high); }
    .val-medium { color: var(--medium); }
    .val-low { color: var(--low); }
    .val-info { color: var(--info); }
    .val-verified { color: var(--verified); }

    .section-title { color: var(--heading); font-size: 1.4rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
    
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 1.5rem;
      overflow: hidden;
    }
    .finding-header {
      padding: 1rem 1.25rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(255, 255, 255, 0.02);
      border-bottom: 1px solid var(--border);
    }
    .finding-title-group { display: flex; align-items: center; gap: 0.75rem; }
    .badge {
      display: inline-block;
      padding: 0.2rem 0.6rem;
      font-size: 0.75rem;
      font-weight: 700;
      border-radius: 4px;
      text-transform: uppercase;
    }
    .badge-critical { background: rgba(248, 81, 73, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .badge-high { background: rgba(219, 109, 40, 0.2); color: var(--high); border: 1px solid var(--high); }
    .badge-medium { background: rgba(210, 153, 34, 0.2); color: var(--medium); border: 1px solid var(--medium); }
    .badge-low { background: rgba(88, 166, 255, 0.2); color: var(--low); border: 1px solid var(--low); }
    .badge-info { background: rgba(139, 148, 158, 0.2); color: var(--info); border: 1px solid var(--info); }
    .badge-verified { background: rgba(63, 185, 80, 0.2); color: var(--verified); border: 1px solid var(--verified); }

    .finding-body { padding: 1.25rem; }
    .finding-field { margin-bottom: 1rem; }
    .finding-field-label { font-weight: 600; color: var(--heading); font-size: 0.9rem; margin-bottom: 0.25rem; }
    
    pre {
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem;
      overflow-x: auto;
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      font-size: 0.85rem;
      color: #e6edf3;
      margin-top: 0.5rem;
    }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #58a6ff; }
    .diff-del { color: #f85149; }
    .diff-add { color: #3fb950; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>${this.escapeHtml(title)}</h1>
      <div class="meta">
        <div class="meta-item"><strong>Assessment ID:</strong> <code>${assessment.assessment_id}</code></div>
        <div class="meta-item"><strong>Phase:</strong> <code>${assessment.phase.toUpperCase()}</code></div>
        <div class="meta-item"><strong>Target:</strong> <code>${assessment.scope.allowed_targets.join(", ")}</code></div>
        <div class="meta-item"><strong>Authorized By:</strong> ${this.escapeHtml(assessment.scope.authorized_by)}</div>
      </div>
    </header>

    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-value val-critical">${assessment.metrics.critical_findings}</div>
        <div class="metric-label">Critical</div>
      </div>
      <div class="metric-card">
        <div class="metric-value val-high">${assessment.metrics.high_findings}</div>
        <div class="metric-label">High</div>
      </div>
      <div class="metric-card">
        <div class="metric-value val-medium">${assessment.metrics.medium_findings}</div>
        <div class="metric-label">Medium</div>
      </div>
      <div class="metric-card">
        <div class="metric-value val-low">${assessment.metrics.low_findings}</div>
        <div class="metric-label">Low</div>
      </div>
      <div class="metric-card">
        <div class="metric-value val-info">${assessment.metrics.info_findings}</div>
        <div class="metric-label">Informational</div>
      </div>
      <div class="metric-card">
        <div class="metric-value val-verified">${assessment.metrics.verified_findings}</div>
        <div class="metric-label">Verified Issues</div>
      </div>
    </div>

    <h2 class="section-title">Security Findings (${sorted.length})</h2>
    ${
      sorted.length === 0
        ? "<p>No security findings detected within the authorized engagement scope.</p>"
        : sorted
            .map(
              (f) => `
      <div class="finding-card">
        <div class="finding-header">
          <div class="finding-title-group">
            <span class="badge badge-${f.severity.level.toLowerCase()}">${f.severity.level}</span>
            <span class="badge badge-verified">${f.verification_status}</span>
            <strong style="color: var(--heading); font-size: 1.1rem;">${this.escapeHtml(f.name)}</strong>
          </div>
          <div>
            ${f.severity.cvss_score ? `<strong>CVSS ${f.severity.cvss_score}</strong>` : ""}
          </div>
        </div>
        <div class="finding-body">
          <div class="finding-field">
            <div class="finding-field-label">Location</div>
            <div><code>${this.escapeHtml(this.formatLocation(f.location))}</code> (Asset: <code>${this.escapeHtml(f.affected_asset.name)}</code>)</div>
          </div>
          <div class="finding-field">
            <div class="finding-field-label">Technical Description</div>
            <p>${this.escapeHtml(f.technical_description)}</p>
          </div>
          <div class="finding-field">
            <div class="finding-field-label">Root Cause Analysis</div>
            <p>${this.escapeHtml(f.root_cause)}</p>
          </div>
          <div class="finding-field">
            <div class="finding-field-label">Impact & Exploitability</div>
            <p><strong>Tier:</strong> <code>${f.impact.exploitability}</code> — ${this.escapeHtml(f.impact.description)}</p>
          </div>
          <div class="finding-field">
            <div class="finding-field-label">Remediation Guidance (Priority: <code>${f.remediation.priority}</code>)</div>
            <p>${this.escapeHtml(f.remediation.description)}</p>
            ${
              f.remediation.code_diff
                ? `<pre><code>${this.formatDiffHtml(f.remediation.code_diff)}</code></pre>`
                : ""
            }
          </div>
          <div class="finding-field">
            <div class="finding-field-label">Provenance & Verification</div>
            <small style="color: var(--info);">Discovered by <code>${this.escapeHtml(f.provenance.discovered_by)}</code> at ${f.provenance.discovered_at}. ID: <code>${f.id}</code></small>
          </div>
        </div>
      </div>`,
            )
            .join("\n")
    }
  </div>
</body>
</html>`;
  }

  // --- Internal Helpers ---

  private formatSeverityBadge(level: string): string {
    switch (level) {
      case "CRITICAL":
        return "CRITICAL";
      case "HIGH":
        return "HIGH";
      case "MEDIUM":
        return "MEDIUM";
      case "LOW":
        return "LOW";
      default:
        return "INFORMATIONAL";
    }
  }

  private formatLocation(loc: FindingLocation): string {
    const parts: string[] = [];
    if (loc.file) {
      parts.push(loc.file);
      if (loc.line) {
        parts.push(`line ${loc.line}`);
      }
    }
    if (loc.function) {
      parts.push(`fn ${loc.function}()`);
    }
    if (loc.address) {
      parts.push(`addr ${loc.address}`);
    }
    return parts.length > 0 ? parts.join(", ") : "Global / Unspecified";
  }

  private compareFindingSeverity(
    a: SecurityFinding,
    b: SecurityFinding,
  ): number {
    const weights: Record<string, number> = {
      CRITICAL: 5,
      HIGH: 4,
      MEDIUM: 3,
      LOW: 2,
      INFORMATIONAL: 1,
    };
    const wa = weights[a.severity.level] ?? 0;
    const wb = weights[b.severity.level] ?? 0;
    if (wb !== wa) {
      return wb - wa;
    }
    return (b.severity.cvss_score ?? 0) - (a.severity.cvss_score ?? 0);
  }

  private countVerified(
    findings: readonly SecurityFinding[],
    level: string,
  ): number {
    return findings.filter(
      (f) => f.severity.level === level && f.verification_status === "VERIFIED",
    ).length;
  }

  private countUnverified(
    findings: readonly SecurityFinding[],
    level: string,
  ): number {
    return findings.filter(
      (f) => f.severity.level === level && f.verification_status !== "VERIFIED",
    ).length;
  }

  private severityToSarifLevel(
    level: string,
  ): "error" | "warning" | "note" | "none" {
    switch (level) {
      case "CRITICAL":
      case "HIGH":
        return "error";
      case "MEDIUM":
        return "warning";
      case "LOW":
      case "INFORMATIONAL":
        return "note";
      default:
        return "none";
    }
  }

  private escapeHtml(text: string): string {
    return text
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  private formatDiffHtml(diff: string): string {
    return diff
      .split("\n")
      .map((line) => {
        const escaped = this.escapeHtml(line);
        if (line.startsWith("+")) {
          return `<span class="diff-add">${escaped}</span>`;
        }
        if (line.startsWith("-")) {
          return `<span class="diff-del">${escaped}</span>`;
        }
        return escaped;
      })
      .join("\n");
  }
}

export const defaultReportGenerator = new SecurityReportGenerator();
