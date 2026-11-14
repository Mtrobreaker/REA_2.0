import { createHash } from "node:crypto";
import { ok, type Result } from "../../../domain/result.js";
import type {
  AdjudicationContext,
  AdjudicationDecision,
  AdjudicationOutcome,
  EvidenceCategory,
} from "../../../domain/security/adjudicate/types.js";
import { guardExistsInExecutableSource } from "./LexicalBlanker.js";
import { evaluateGuardSemantics } from "./SemanticGuardEvaluator.js";

/**
 * MultiStageAdjudicator
 * Production anti-hallucination and multi-stage vulnerability verification engine.
 */
export class MultiStageAdjudicator {
  /**
   * Evaluates a security finding candidate across 4 verification gates.
   */
  public adjudicate(context: AdjudicationContext): Result<AdjudicationDecision, never> {
    const now = Date.now();
    const evidenceHashes: string[] = [
      ...(context.prior_evidence_hashes ?? []),
      createHash("sha256")
        .update(context.source_code, "utf8")
        .digest("hex"),
    ];

    // Anti-fabrication check: missing or empty source code cannot verify a finding
    if (!context.source_code || context.source_code.trim().length === 0) {
      const decision: AdjudicationDecision = {
        finding_id: context.finding_id,
        outcome: "INCONCLUSIVE",
        confidence_score: 0.3,
        evidence_category: context.evidence_category,
        reasoning: "Source code missing or unavailable; cannot verify vulnerability",
        evidence_hashes: evidenceHashes,
        evaluated_at: now,
      };
      return ok(decision);
    }

    // Case A: No guard was claimed by the model or scanner
    if (!context.claimed_guard_expression) {
      const decision: AdjudicationDecision = {
        finding_id: context.finding_id,
        outcome: "CONFIRMED_VULNERABLE",
        confidence_score: this.computeConfidence(
          "CONFIRMED_VULNERABLE",
          context.evidence_category,
        ),
        evidence_category: context.evidence_category,
        reasoning: "No mitigating guard claimed; sink remains unconstrained",
        evidence_hashes: evidenceHashes,
        evaluated_at: now,
      };
      return ok(decision);
    }

    // Gate 1: Lexical Existence Check (Anti-Hallucination)
    const existence = guardExistsInExecutableSource(
      context.source_code,
      context.claimed_guard_expression,
      context.language ?? "c",
    );

    if (!existence.exists) {
      // Hallucinated guard: The model invented a check that does not physically exist in executable code
      const decision: AdjudicationDecision = {
        finding_id: context.finding_id,
        outcome: "CONFIRMED_VULNERABLE",
        confidence_score: this.computeConfidence(
          "CONFIRMED_VULNERABLE",
          context.evidence_category,
        ),
        evidence_category: context.evidence_category,
        reasoning: `Claimed guard '${context.claimed_guard_expression}' does not physically exist in executable source (hallucination rejected)`,
        evidence_hashes: evidenceHashes,
        evaluated_at: now,
      };
      return ok(decision);
    }

    // Gate 2 & 3: Semantic Guard Soundness, Dominance & Type Checks
    const semantics = evaluateGuardSemantics({
      guard_expression: context.claimed_guard_expression,
      guard_line: existence.matched_line ?? context.claimed_guard_line,
      sink_expression: context.sink_expression,
      sink_line: context.sink_line,
      tainted_variable: context.tainted_variable,
      source_code: context.source_code,
    });

    if (semantics.is_undecidable) {
      const decision: AdjudicationDecision = {
        finding_id: context.finding_id,
        outcome: "INCONCLUSIVE",
        confidence_score: 0.4,
        evidence_category: context.evidence_category,
        reasoning: `Analysis undecidable: ${semantics.reason}`,
        dominating_guard: {
          ...semantics.analysis,
          file: context.file_path,
        },
        evidence_hashes: evidenceHashes,
        evaluated_at: now,
      };
      return ok(decision);
    }

    if (!semantics.is_sound) {
      // Flawed guard: The check exists, but is inverted, checks wrong operand, or does not dominate the sink
      const decision: AdjudicationDecision = {
        finding_id: context.finding_id,
        outcome: "FLAWED_GUARD",
        confidence_score: this.computeConfidence(
          "FLAWED_GUARD",
          context.evidence_category,
        ),
        evidence_category: context.evidence_category,
        reasoning: `Ineffective guard detected: ${semantics.reason}`,
        dominating_guard: {
          ...semantics.analysis,
          file: context.file_path,
        },
        evidence_hashes: evidenceHashes,
        evaluated_at: now,
      };
      return ok(decision);
    }

    // Gate 4: Sound Guard Confirmed
    const decision: AdjudicationDecision = {
      finding_id: context.finding_id,
      outcome: "CONFIRMED_MITIGATED",
      confidence_score: this.computeConfidence(
        "CONFIRMED_MITIGATED",
        context.evidence_category,
      ),
      evidence_category: context.evidence_category,
      reasoning: `Valid dominating guard verified in source: ${semantics.reason}`,
      dominating_guard: {
        ...semantics.analysis,
        file: context.file_path,
      },
      evidence_hashes: evidenceHashes,
      evaluated_at: now,
    };

    return ok(decision);
  }

  /**
   * Computes confidence score bounded strictly by evidence category ceilings.
   */
  private computeConfidence(
    outcome: AdjudicationOutcome,
    category: EvidenceCategory,
  ): number {
    switch (category) {
      case "STATIC_AST_CFG":
        // Static analysis alone is capped at 0.80
        return outcome === "CONFIRMED_MITIGATED" ? 0.75 : 0.8;
      case "SYNTHETIC_FIXTURE":
        // Test fixtures in harnesses capped at 0.85
        return outcome === "CONFIRMED_MITIGATED" ? 0.8 : 0.85;
      case "TARGET_OBSERVATION":
        // Real authorized target verification achieves highest confidence
        return outcome === "CONFIRMED_MITIGATED" ? 0.95 : 1.0;
    }
  }
}
