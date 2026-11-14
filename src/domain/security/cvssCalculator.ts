import { err, ok, type Result } from "../result.js";
import type { SecuritySeverityLevel } from "./classification.js";

/**
 * CVSS v3.1 Base Metric Dimensions.
 */
export type AttackVector = "N" | "A" | "L" | "P";
export type AttackComplexity = "L" | "H";
export type PrivilegesRequired = "N" | "L" | "H";
export type UserInteraction = "N" | "R";
export type Scope = "U" | "C";
export type ImpactMetric = "N" | "L" | "H";

export interface Cvss31Metrics {
  readonly attack_vector: AttackVector;
  readonly attack_complexity: AttackComplexity;
  readonly privileges_required: PrivilegesRequired;
  readonly user_interaction: UserInteraction;
  readonly scope: Scope;
  readonly confidentiality_impact: ImpactMetric;
  readonly integrity_impact: ImpactMetric;
  readonly availability_impact: ImpactMetric;
}

export interface Cvss31CalculationResult {
  readonly score: number;
  readonly severity: SecuritySeverityLevel;
  readonly vector_string: string;
  readonly exploitability_subscore: number;
  readonly impact_subscore: number;
}

export interface CvssParseError {
  readonly code: "INVALID_VECTOR" | "MISSING_METRIC" | "UNKNOWN_METRIC_VALUE";
  readonly message: string;
}

// Numerical metric weights according to CVSS v3.1 specification (Section 7.1)
const AV_WEIGHTS: Record<AttackVector, number> = {
  N: 0.85,
  A: 0.62,
  L: 0.55,
  P: 0.2,
};

const AC_WEIGHTS: Record<AttackComplexity, number> = {
  L: 0.77,
  H: 0.44,
};

const UI_WEIGHTS: Record<UserInteraction, number> = {
  N: 0.85,
  R: 0.62,
};

const IMPACT_WEIGHTS: Record<ImpactMetric, number> = {
  N: 0.0,
  L: 0.22,
  H: 0.56,
};

const PR_WEIGHTS: Record<
  Scope,
  Record<PrivilegesRequired, number>
> = {
  U: {
    N: 0.85,
    L: 0.62,
    H: 0.27,
  },
  C: {
    N: 0.85,
    L: 0.68,
    H: 0.5,
  },
};

/**
 * The official CVSS v3.1 Roundup function.
 * Rounds up to one decimal place per FIRST.org Section 7.4.
 */
export const cvssRoundUp = (input: number): number => {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000;
  }
  return (Math.floor(intInput / 10000) + 1) / 10;
};

/**
 * Convert numeric CVSS score to qualitative severity rating.
 */
export const cvssScoreToSeverity = (score: number): SecuritySeverityLevel => {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0.0) return "LOW";
  return "INFORMATIONAL";
};

/**
 * Format a Cvss31Metrics object into a canonical CVSS:3.1 vector string.
 */
export const formatCvss31Vector = (metrics: Cvss31Metrics): string => {
  return (
    `CVSS:3.1/AV:${metrics.attack_vector}` +
    `/AC:${metrics.attack_complexity}` +
    `/PR:${metrics.privileges_required}` +
    `/UI:${metrics.user_interaction}` +
    `/S:${metrics.scope}` +
    `/C:${metrics.confidentiality_impact}` +
    `/I:${metrics.integrity_impact}` +
    `/A:${metrics.availability_impact}`
  );
};

/**
 * Parse a standard CVSS v3.1 vector string into structured metrics.
 * Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
 */
export const parseCvss31Vector = (
  vector: string,
): Result<Cvss31Metrics, CvssParseError> => {
  if (!vector.startsWith("CVSS:3.1/")) {
    return err({
      code: "INVALID_VECTOR",
      message: "Vector string must start with 'CVSS:3.1/'",
    });
  }

  const parts = vector.slice("CVSS:3.1/".length).split("/");
  const dict = new Map<string, string>();

  for (const part of parts) {
    const [key, value] = part.split(":");
    if (!key || !value) {
      return err({
        code: "INVALID_VECTOR",
        message: `Malformed metric element: '${part}'`,
      });
    }
    dict.set(key, value);
  }

  const av = dict.get("AV");
  if (!av || !["N", "A", "L", "P"].includes(av)) {
    return err({
      code: "UNKNOWN_METRIC_VALUE",
      message: `Invalid or missing Attack Vector (AV): '${av}'`,
    });
  }

  const ac = dict.get("AC");
  if (!ac || !["L", "H"].includes(ac)) {
    return err({
      code: "UNKNOWN_METRIC_VALUE",
      message: `Invalid or missing Attack Complexity (AC): '${ac}'`,
    });
  }

  const pr = dict.get("PR");
  if (!pr || !["N", "L", "H"].includes(pr)) {
    return err({
      code: "UNKNOWN_METRIC_VALUE",
      message: `Invalid or missing Privileges Required (PR): '${pr}'`,
    });
  }

  const ui = dict.get("UI");
  if (!ui || !["N", "R"].includes(ui)) {
    return err({
      code: "UNKNOWN_METRIC_VALUE",
      message: `Invalid or missing User Interaction (UI): '${ui}'`,
    });
  }

  const s = dict.get("S");
  if (!s || !["U", "C"].includes(s)) {
    return err({
      code: "UNKNOWN_METRIC_VALUE",
      message: `Invalid or missing Scope (S): '${s}'`,
    });
  }

  const c = dict.get("C");
  if (!c || !["N", "L", "H"].includes(c)) {
    return err({
      code: "UNKNOWN_METRIC_VALUE",
      message: `Invalid or missing Confidentiality Impact (C): '${c}'`,
    });
  }

  const i = dict.get("I");
  if (!i || !["N", "L", "H"].includes(i)) {
    return err({
      code: "UNKNOWN_METRIC_VALUE",
      message: `Invalid or missing Integrity Impact (I): '${i}'`,
    });
  }

  const a = dict.get("A");
  if (!a || !["N", "L", "H"].includes(a)) {
    return err({
      code: "UNKNOWN_METRIC_VALUE",
      message: `Invalid or missing Availability Impact (A): '${a}'`,
    });
  }

  return ok({
    attack_vector: av as AttackVector,
    attack_complexity: ac as AttackComplexity,
    privileges_required: pr as PrivilegesRequired,
    user_interaction: ui as UserInteraction,
    scope: s as Scope,
    confidentiality_impact: c as ImpactMetric,
    integrity_impact: i as ImpactMetric,
    availability_impact: a as ImpactMetric,
  });
};

/**
 * Calculate CVSS v3.1 Base Score and Sub-Scores from metrics.
 */
export const calculateCvss31BaseScore = (
  metrics: Cvss31Metrics,
): Cvss31CalculationResult => {
  const av = AV_WEIGHTS[metrics.attack_vector];
  const ac = AC_WEIGHTS[metrics.attack_complexity];
  const pr = PR_WEIGHTS[metrics.scope][metrics.privileges_required];
  const ui = UI_WEIGHTS[metrics.user_interaction];

  const c = IMPACT_WEIGHTS[metrics.confidentiality_impact];
  const i = IMPACT_WEIGHTS[metrics.integrity_impact];
  const a = IMPACT_WEIGHTS[metrics.availability_impact];

  // Impact Sub-Score (ISS)
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);

  // Impact Score
  let impact = 0;
  if (metrics.scope === "U") {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  // Exploitability Score
  const exploitability = 8.22 * av * ac * pr * ui;

  // Base Score
  let baseScore = 0;
  if (impact <= 0) {
    baseScore = 0.0;
  } else if (metrics.scope === "U") {
    baseScore = cvssRoundUp(Math.min(impact + exploitability, 10.0));
  } else {
    baseScore = cvssRoundUp(Math.min(1.08 * (impact + exploitability), 10.0));
  }

  const vectorString = formatCvss31Vector(metrics);
  const severity = cvssScoreToSeverity(baseScore);

  return {
    score: baseScore,
    severity,
    vector_string: vectorString,
    exploitability_subscore: cvssRoundUp(exploitability),
    impact_subscore: cvssRoundUp(impact),
  };
};

/**
 * Convenience helper to calculate CVSS score directly from a vector string.
 */
export const calculateCvss31FromVector = (
  vector: string,
): Result<Cvss31CalculationResult, CvssParseError> => {
  const parsed = parseCvss31Vector(vector);
  if (!parsed.ok) {
    return parsed;
  }
  return ok(calculateCvss31BaseScore(parsed.value));
};

