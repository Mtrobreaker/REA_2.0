import { z } from "zod";
import type { FindingId } from "../finding.js";

export const ADJUDICATION_OUTCOMES = [
  "CONFIRMED_VULNERABLE",
  "CONFIRMED_MITIGATED",
  "FLAWED_GUARD",
  "INCONCLUSIVE",
] as const;

export type AdjudicationOutcome = (typeof ADJUDICATION_OUTCOMES)[number];

export const adjudicationOutcomeSchema = z.enum(ADJUDICATION_OUTCOMES);

export const EVIDENCE_CATEGORIES = [
  "STATIC_AST_CFG",
  "SYNTHETIC_FIXTURE",
  "TARGET_OBSERVATION",
] as const;

export type EvidenceCategory = (typeof EVIDENCE_CATEGORIES)[number];

export const evidenceCategorySchema = z.enum(EVIDENCE_CATEGORIES);

/**
 * Detailed analysis of an identified code guard/bounds check.
 */
export interface DominatingGuardAnalysis {
  readonly file: string;
  readonly line: number;
  readonly expression: string;
  readonly dominates_all_paths: boolean;
  readonly operand_matched: boolean;
  readonly operator_sound: boolean;
  readonly signedness_safe: boolean;
}

export const dominatingGuardAnalysisSchema = z.strictObject({
  file: z.string().min(1),
  line: z.number().int().min(1),
  expression: z.string().min(1),
  dominates_all_paths: z.boolean(),
  operand_matched: z.boolean(),
  operator_sound: z.boolean(),
  signedness_safe: z.boolean(),
});

/**
 * Formal verdict emitted by the Adjudicate verification engine.
 */
export interface AdjudicationDecision {
  readonly finding_id: FindingId;
  readonly outcome: AdjudicationOutcome;
  readonly confidence_score: number; // 0.00 to 1.00
  readonly evidence_category: EvidenceCategory;
  readonly reasoning: string;
  readonly dominating_guard?: DominatingGuardAnalysis | undefined;
  readonly evidence_hashes: readonly string[];
  readonly evaluated_at: number;
}

export const adjudicationDecisionSchema = z.strictObject({
  finding_id: z.string().startsWith("fnd_") as unknown as z.ZodType<FindingId>,
  outcome: adjudicationOutcomeSchema,
  confidence_score: z.number().min(0).max(1),
  evidence_category: evidenceCategorySchema,
  reasoning: z.string().min(1),
  dominating_guard: dominatingGuardAnalysisSchema.optional(),
  evidence_hashes: z.array(z.string()).default([]),
  evaluated_at: z.number().int().nonnegative(),
});

/**
 * Context payload provided to the Adjudicate engine for evaluation.
 */
export interface AdjudicationContext {
  readonly finding_id: FindingId;
  readonly source_code: string;
  readonly file_path: string;
  readonly language?: string | undefined;
  readonly claimed_guard_expression?: string | undefined;
  readonly claimed_guard_line?: number | undefined;
  readonly sink_expression?: string | undefined;
  readonly sink_line?: number | undefined;
  readonly tainted_variable?: string | undefined;
  readonly evidence_category: EvidenceCategory;
  readonly prior_evidence_hashes?: readonly string[] | undefined;
}

