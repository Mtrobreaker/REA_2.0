import { ok, type Result } from "../../domain/result.js";
import type { SecurityFinding } from "../../domain/security/finding.js";
import {
  defaultCveDatabase,
  type CveDatabase,
} from "../intelligence/cveDatabase.js";
import type {
  AgentContext,
  AgentExecutionError,
  AgentExecutionResult,
  SecurityAgent,
} from "./types.js";

/**
 * Threat Intelligence Agent
 * Correlates findings with CVE, CWE, CAPEC, and MITRE ATT&CK taxonomies,
 * enriching findings with known exploitation vectors, CVSS scores, and threat context.
 */
export class ThreatIntelligenceAgent implements SecurityAgent {
  public readonly role = "threat_intelligence";
  public readonly name = "Threat Intelligence & Taxonomy Agent";
  public readonly description =
    "Enriches findings with CVE details, MITRE ATT&CK techniques, CAPEC attack patterns, and standard CVSS v3.1 scoring.";

  constructor(private readonly cveDb: CveDatabase = defaultCveDatabase) {}

  public async execute(
    context: AgentContext,
  ): Promise<Result<AgentExecutionResult, AgentExecutionError>> {
    const findings = context.state.findings;
    const actions: string[] = [];
    const enrichedFindings: SecurityFinding[] = [];

    if (findings.length === 0) {
      actions.push("No findings available for threat intelligence enrichment.");
      return ok({
        agent_role: this.role,
        actions_performed: actions,
        findings_added: [],
        findings_modified: [],
        assets_added: [],
      });
    }

    for (const f of findings) {
      const enriched = this.cveDb.enrichFinding(f);
      if (
        enriched.classification.cve.length > f.classification.cve.length ||
        enriched.severity.cvss_score !== f.severity.cvss_score
      ) {
        actions.push(
          `Enriched finding '${f.name}' with threat intelligence (Score: ${enriched.severity.cvss_score ?? "N/A"})`,
        );
      }
      enrichedFindings.push(enriched);
    }

    if (enrichedFindings.length > 0) {
      const updatedMap = new Map<string, SecurityFinding>(
        enrichedFindings.map((f) => [f.id, f]),
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
      findings_modified: enrichedFindings,
      assets_added: [],
    });
  }
}

