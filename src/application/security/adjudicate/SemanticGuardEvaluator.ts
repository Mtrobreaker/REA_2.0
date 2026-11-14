import type { DominatingGuardAnalysis } from "../../../domain/security/adjudicate/types.js";

export interface SemanticEvaluationInput {
  readonly guard_expression: string;
  readonly guard_line?: number | undefined;
  readonly sink_expression?: string | undefined;
  readonly sink_line?: number | undefined;
  readonly tainted_variable?: string | undefined;
  readonly source_code: string;
}

export interface SemanticEvaluationResult {
  readonly is_sound: boolean;
  readonly is_undecidable: boolean;
  readonly reason: string;
  readonly analysis: DominatingGuardAnalysis;
}

/**
 * Analyzes whether an identified guard expression is semantically effective at mitigating the vulnerability.
 */
export function evaluateGuardSemantics(
  input: SemanticEvaluationInput,
): SemanticEvaluationResult {
  const expr = input.guard_expression.trim();
  const tainted = input.tainted_variable?.trim();

  // 1. Operand Matching Check
  // The guard must test the variable that actually controls the sensitive sink.
  let operandMatched = true;
  if (tainted) {
    const operandRegex = new RegExp(`\\b${tainted}\\b`, "u");
    operandMatched = operandRegex.test(expr);
  }

  // 2. Control Flow Dominance (Basic intra-procedural line order check)
  let dominatesAllPaths = true;
  if (input.guard_line && input.sink_line) {
    if (input.guard_line >= input.sink_line) {
      // Guard is on or after the sink line: cannot dominate!
      dominatesAllPaths = false;
    }
  }

  // 3. Operator Soundness Check
  // Bounds checks generally test `<` or `<=` against a upper limit, or `>` against 0/minimum.
  let operatorSound = true;
  if (expr.includes("==") && !expr.includes("!=") && !expr.includes("<") && !expr.includes(">")) {
    // Exact equality check is rarely a sound bounds check for general buffers
    operatorSound = false;
  }

  // Check for inverted bounds logic (e.g. `var > MAX` without an exit/return block)
  if (expr.includes(">") && !expr.includes("<")) {
    // If it's `var > MAX`, it is only sound if it triggers an error/exit
    const sourceAfterGuard = input.source_code.slice(
      input.source_code.indexOf(expr) + expr.length,
      input.source_code.indexOf(expr) + expr.length + 200,
    );
    const hasExit =
      /\b(return|goto\s+error|goto\s+err|exit|abort|break|throw)\b/i.test(
        sourceAfterGuard,
      );
    if (!hasExit) {
      operatorSound = false;
    }
  }

  // 4. Signedness Safety Check
  // In C/C++, checking `len < MAX` where `len` is signed does not protect against negative values
  let signednessSafe = true;
  if (tainted && input.source_code.includes(`int ${tainted}`)) {
    const lines = input.source_code.split("\n");
    const guardLineText = input.guard_line ? (lines[input.guard_line - 1] ?? "") : "";
    const hasZeroCheck =
      new RegExp(`\\b${tainted}\\s*(>=|>)\\s*0\\b`).test(expr) ||
      new RegExp(`0\\s*(<=|<)\\s*\\b${tainted}\\b`).test(expr) ||
      new RegExp(`\\b${tainted}\\s*(>=|>)\\s*0\\b`).test(guardLineText) ||
      new RegExp(`0\\s*(<=|<)\\s*\\b${tainted}\\b`).test(guardLineText);

    if (!hasZeroCheck && (expr.includes("<") || expr.includes("<="))) {
      signednessSafe = false;
    }
  }

  // 5. Undecidability Heuristics
  // Check for complex macros, pointer dereferences, or external calls that obscure flow
  const isUndecidable =
    /\b(setjmp|longjmp|alloca)\b/i.test(input.source_code) ||
    (expr.includes("*") && expr.includes("->")); // Complex pointer chasing

  const isSound =
    operandMatched &&
    dominatesAllPaths &&
    operatorSound &&
    signednessSafe &&
    !isUndecidable;

  let reason = "Guard is semantically sound and dominates sink path";
  if (!operandMatched) {
    reason = `Guard tests wrong operand (expected '${tainted}', got '${expr}')`;
  } else if (!dominatesAllPaths) {
    reason = `Guard at line ${input.guard_line} does not dominate sink at line ${input.sink_line}`;
  } else if (!operatorSound) {
    reason = `Guard has ineffective or inverted comparison logic in '${expr}'`;
  } else if (!signednessSafe) {
    reason = `Guard checks upper bound on signed integer '${tainted}' without non-negative check`;
  } else if (isUndecidable) {
    reason = "Analysis undecidable due to pointer aliasing or dynamic control transfer";
  }

  return {
    is_sound: isSound,
    is_undecidable: isUndecidable,
    reason,
    analysis: {
      file: "source",
      line: input.guard_line ?? 1,
      expression: expr,
      dominates_all_paths: dominatesAllPaths,
      operand_matched: operandMatched,
      operator_sound: operatorSound,
      signedness_safe: signednessSafe,
    },
  };
}
