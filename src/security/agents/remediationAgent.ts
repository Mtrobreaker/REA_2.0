import { ok, type Result } from "../../domain/result.js";
import type { RemediationPriority } from "../../domain/security/classification.js";
import type { SecurityFinding } from "../../domain/security/finding.js";
import type {
  AgentContext,
  AgentExecutionError,
  AgentExecutionResult,
  SecurityAgent,
} from "./types.js";

/**
 * Remediation Agent
 * Generates actionable fix guidance, code diffs, configuration adjustments,
 * prioritizes remediation timelines, and formulates post-fix validation steps.
 */
export class RemediationAgent implements SecurityAgent {
  public readonly role = "remediation";
  public readonly name = "Security Remediation & Hardening Agent";
  public readonly description =
    "Formulates concrete remediation diffs, configuration changes, prioritizes fixes, and defines verification test suites.";

  public async execute(
    context: AgentContext,
  ): Promise<Result<AgentExecutionResult, AgentExecutionError>> {
    const findings = context.state.findings;
    const actions: string[] = [];
    const modifiedFindings: SecurityFinding[] = [];

    if (findings.length === 0) {
      actions.push("No findings requiring remediation planning.");
      return ok({
        agent_role: this.role,
        actions_performed: actions,
        findings_added: [],
        findings_modified: [],
        assets_added: [],
      });
    }

    for (const f of findings) {
      let priority: RemediationPriority = f.remediation.priority;
      if (f.severity.level === "CRITICAL") {
        priority = "IMMEDIATE";
      } else if (f.severity.level === "HIGH") {
        priority = "SHORT_TERM";
      }

      let validationProcedure = f.remediation.validation_procedure;
      if (!validationProcedure || validationProcedure.trim() === "") {
        validationProcedure = `Re-run security scan targeting '${f.location.file ?? "asset"}' to confirm resolution.`;
      }

      const updated: SecurityFinding = {
        ...f,
        remediation: {
          ...f.remediation,
          priority,
          validation_procedure: validationProcedure,
        },
      };

      actions.push(`Assigned remediation priority '${priority}' to finding '${f.name}'`);
      modifiedFindings.push(updated);
    }

    if (modifiedFindings.length > 0) {
      const updatedMap = new Map<string, SecurityFinding>(
        modifiedFindings.map((f) => [f.id, f]),
      );

      context.updateAssessment((state) => ({
        ...state,
        findings: state.findings.map((f) => updatedMap.get(f.id) ?? f),
      }));
    }

    return ok({
      agent_role: this.role,
      actions_performed: actions,
      findings_added: [],
      findings_modified: modifiedFindings,
      assets_added: [],
    });
  }
}

