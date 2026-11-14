import { ok, err, type Result } from "../../domain/result.js";
import type { SecurityFinding } from "../../domain/security/finding.js";
import { runSemgrepScan } from "../tools/adapters/semgrepAdapter.js";
import type {
  AgentContext,
  AgentExecutionError,
  AgentExecutionResult,
  SecurityAgent,
} from "./types.js";

/**
 * Software Security Agent
 * Conducts deep source-code security analysis, identifies insecure coding patterns,
 * evaluates logic flaws, and emits structured security finding proposals.
 */
export class SoftwareSecurityAgent implements SecurityAgent {
  public readonly role = "software_security";
  public readonly name = "Source Code & Software Security Agent";
  public readonly description =
    "Analyzes application source code, frameworks, and libraries to detect vulnerabilities, dangerous API usage, and insecure patterns.";

  public async execute(
    context: AgentContext,
  ): Promise<Result<AgentExecutionResult, AgentExecutionError>> {
    const assets = context.state.assets.filter(
      (a) => a.type === "source_repository",
    );
    const actions: string[] = [];
    const proposedFindings: SecurityFinding[] = [];

    if (assets.length === 0) {
      actions.push("No source code repository assets present for evaluation.");
      return ok({
        agent_role: this.role,
        actions_performed: actions,
        findings_added: [],
        findings_modified: [],
        assets_added: [],
      });
    }

    for (const asset of assets) {
      if (!asset.path) continue;
      actions.push(`Running static analysis on source asset: ${asset.name}`);

      const scanResult = await runSemgrepScan({
        targets: [asset.path],
        asset,
        ...(context.signal !== undefined ? { signal: context.signal } : {}),
      });

      if (scanResult.ok) {
        actions.push(
          `Semgrep analysis discovered ${scanResult.value.findings.length} finding candidate(s)`,
        );
        for (const finding of scanResult.value.findings) {
          proposedFindings.push(finding);
          context.postMessage({
            sender: this.role,
            recipient: "verification",
            kind: "FINDING_PROPOSAL",
            payload: { finding_id: finding.id, name: finding.name },
          });
        }
      } else {
        actions.push(
          `Semgrep scan warning for ${asset.name}: ${scanResult.error.message}`,
        );
      }
    }

    // Add findings to assessment state
    if (proposedFindings.length > 0) {
      context.updateAssessment((state) => ({
        ...state,
        findings: [...state.findings, ...proposedFindings],
      }));
    }

    return ok({
      agent_role: this.role,
      actions_performed: actions,
      findings_added: proposedFindings,
      findings_modified: [],
      assets_added: [],
    });
  }
}

