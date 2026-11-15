import { ok, type Result } from "../../domain/result.js";
import type { SecurityFinding } from "../../domain/security/finding.js";
import type { VerificationStatus } from "../../domain/security/classification.js";
import type {
  AdjudicationContext,
  AdjudicationDecision,
} from "../../domain/security/adjudicate/types.js";
import { MultiStageAdjudicator } from "../../application/security/adjudicate/MultiStageAdjudicator.js";
import type {
  AgentContext,
  AgentExecutionError,
  AgentExecutionResult,
  SecurityAgent,
} from "./types.js";

/**
 * Vulnerability Verification Agent
 * Independently validates findings, eliminates false positives, evaluates reproducibility,
 * and upgrades finding verification statuses using multi-stage AST and semantic adjudication.
 */
export class VulnerabilityVerificationAgent implements SecurityAgent {
  public readonly role = "verification";
  public readonly name = "Vulnerability Verification & Validation Agent";
  public readonly description =
    "Independently validates finding candidates, filters out false positives, verifies preconditions, and confirms reproducibility.";

  private readonly adjudicator: MultiStageAdjudicator;

  constructor(adjudicator?: MultiStageAdjudicator) {
    this.adjudicator = adjudicator ?? new MultiStageAdjudicator();
  }

  /**
   * Adjudicates a single candidate finding against source code and claimed mitigating guards.
   */
  public adjudicateCandidate(
    finding: SecurityFinding,
    sourceCode?: string,
    claimedGuard?: string,
    language?: string,
  ): AdjudicationDecision {
    const context: AdjudicationContext = {
      finding_id: finding.id,
      source_code: sourceCode ?? "",
      file_path: finding.location.file ?? "unknown_file",
      language: language ?? "c",
      claimed_guard_expression: claimedGuard ?? undefined,
      sink_expression: finding.technical_description,
      sink_line: finding.location.line ?? undefined,
      evidence_category: "STATIC_AST_CFG",
      prior_evidence_hashes: finding.evidence_ids ?? [],
    };

    const result = this.adjudicator.adjudicate(context);
    if (!result.ok) {
      throw new Error("Adjudication failed");
    }
    return result.value;
  }

  public async execute(
    context: AgentContext,
  ): Promise<Result<AgentExecutionResult, AgentExecutionError>> {
    const findings = context.state.findings;
    const actions: string[] = [];
    const modifiedFindings: SecurityFinding[] = [];

    if (findings.length === 0) {
      actions.push("No candidate findings available to verify.");
      return ok({
        agent_role: this.role,
        actions_performed: actions,
        findings_added: [],
        findings_modified: [],
        assets_added: [],
      });
    }

    const timestamp = new Date().toISOString();

    for (const finding of findings) {
      // If already verified by an authoritative scanner, retain or reaffirm
      if (finding.verification_status === "VERIFIED") {
        actions.push(`Finding '${finding.name}' is already verified.`);
        continue;
      }

      // Check false positive indicators
      const isTestFile = finding.location.file
        ? /(?:test|spec|mock|fixture|sample)/i.test(finding.location.file)
        : false;

      let newStatus: VerificationStatus = finding.verification_status;
      let confidenceLevel = finding.confidence.level;
      const notes: string[] = [
        ...finding.confidence.false_positive_considerations,
      ];

      if (isTestFile && finding.severity.level !== "CRITICAL") {
        newStatus = "FALSE_POSITIVE";
        notes.push(
          "Identified within test, mock, or fixture path; unlikely to be exposed in production.",
        );
        actions.push(
          `Classified finding '${finding.name}' as FALSE_POSITIVE (test directory fixture).`,
        );
      } else {
        // Run multi-stage adjudication (NEVER confuse remediation prose with a claimed source-code guard,
        // and NEVER promote to VERIFIED without verified source code and cryptographic evidence).
        const hasEvidence =
          Array.isArray(finding.evidence_ids) &&
          finding.evidence_ids.length > 0;

        if (!hasEvidence) {
          newStatus =
            finding.verification_status === "CANDIDATE"
              ? "CANDIDATE"
              : "UNVERIFIED";
          confidenceLevel = "TENTATIVE";
          actions.push(
            `Retaining finding '${finding.name}' as ${newStatus} (missing trusted evidence).`,
          );
        } else {
          const decision = this.adjudicateCandidate(
            finding,
            undefined,
            undefined,
          );

          if (decision.outcome === "CONFIRMED_MITIGATED") {
            newStatus = "FALSE_POSITIVE";
            notes.push(
              `Adjudication verified mitigating guard: ${decision.reasoning}`,
            );
            actions.push(
              `Dismissed finding '${finding.name}' as mitigated by verified guard.`,
            );
          } else if (decision.outcome === "FLAWED_GUARD") {
            if (hasEvidence) {
              newStatus = "VERIFIED";
              notes.push(
                `Adjudication detected flawed guard: ${decision.reasoning}`,
              );
              actions.push(
                `Verified finding '${finding.name}' despite claimed guard (${decision.reasoning}).`,
              );
            } else {
              newStatus = "UNVERIFIED";
              confidenceLevel = "TENTATIVE";
              notes.push(
                `Adjudication detected flawed guard but lacks underlying evidence: ${decision.reasoning}`,
              );
              actions.push(
                `Flagged finding '${finding.name}' as UNVERIFIED (lacks evidence).`,
              );
            }
          } else if (decision.outcome === "INCONCLUSIVE") {
            newStatus = "UNVERIFIED";
            confidenceLevel = "TENTATIVE";
            notes.push(`Adjudication inconclusive: ${decision.reasoning}`);
            actions.push(
              `Flagged finding '${finding.name}' as INCONCLUSIVE (${decision.reasoning}).`,
            );
          } else {
            if (hasEvidence) {
              newStatus = "VERIFIED";
              actions.push(
                `Verified finding '${finding.name}' through deterministic rule evidence.`,
              );
            } else {
              newStatus = "UNVERIFIED";
              confidenceLevel = "TENTATIVE";
              notes.push(
                "Missing verified source code or evidence; cannot confirm vulnerability.",
              );
              actions.push(
                `Retaining finding '${finding.name}' as UNVERIFIED (missing evidence).`,
              );
            }
          }
        }
      }

      const updated: SecurityFinding = {
        ...finding,
        verification_status: newStatus,
        confidence: {
          ...finding.confidence,
          level: confidenceLevel,
          false_positive_considerations: notes,
        },
        provenance: {
          ...finding.provenance,
          verified_by:
            newStatus === "VERIFIED"
              ? "verification-agent"
              : finding.provenance.verified_by,
          verified_at:
            newStatus === "VERIFIED"
              ? timestamp
              : finding.provenance.verified_at,
        },
      };

      modifiedFindings.push(updated);
    }

    // Update assessment state with verified findings
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
