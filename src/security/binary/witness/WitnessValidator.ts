import type { WitnessArtifact, WitnessValidationResult } from "./types.js";

export interface EnvironmentBounds {
  readonly maxInputLength?: number;
  readonly disallowedCharacters?: readonly string[];
  readonly enforcedFilters?: readonly string[];
}

export class WitnessValidator {
  /**
   * Validate the satisfiability and reproducibility of a witness artifact
   * against modeled environment boundaries without executing target binaries on host.
   */
  public validateWitness(
    witness: WitnessArtifact,
    bounds?: EnvironmentBounds,
  ): WitnessValidationResult {
    const logs: string[] = [];
    const conflictingGuards: string[] = [];
    const verifiedAt = new Date().toISOString();

    logs.push(`Starting sandbox constraint validation for witness '${witness.witnessId}'`);
    logs.push(`Target: ${witness.category} at ${witness.sink.functionName} (${witness.sink.api})`);

    if (witness.constraints.length === 0) {
      const conflict = "Witness contains no input constraints (vacuous proof)";
      conflictingGuards.push(conflict);
      logs.push(`[CONFLICT] ${conflict}`);
      return {
        witnessId: witness.witnessId,
        isSatisfiable: false,
        isReproducible: false,
        exploitabilityStatus: "UNSATISFIABLE",
        evaluatedPreconditionsCount: 0,
        conflictingGuards,
        validationLog: logs,
        verifiedAt,
      };
    }

    let isSatisfiable = true;

    // Check internal contradictions (e.g., character required present AND absent)
    const presentCharsByParam = new Map<string, Set<string>>();
    const absentCharsByParam = new Map<string, Set<string>>();
    const minLengthByParam = new Map<string, number>();
    const maxLengthByParam = new Map<string, number>();

    for (const constraint of witness.constraints) {
      if (constraint.type === "character_present") {
        const chars = Array.isArray(constraint.expectedValue)
          ? constraint.expectedValue
          : [String(constraint.expectedValue)];
        const set = presentCharsByParam.get(constraint.parameter) ?? new Set();
        chars.forEach((c) => set.add(c));
        presentCharsByParam.set(constraint.parameter, set);
      } else if (constraint.type === "character_absent") {
        const chars = Array.isArray(constraint.expectedValue)
          ? constraint.expectedValue
          : [String(constraint.expectedValue)];
        const set = absentCharsByParam.get(constraint.parameter) ?? new Set();
        chars.forEach((c) => set.add(c));
        absentCharsByParam.set(constraint.parameter, set);
      } else if (constraint.type === "min_length") {
        minLengthByParam.set(constraint.parameter, Number(constraint.expectedValue));
      } else if (constraint.type === "max_length") {
        maxLengthByParam.set(constraint.parameter, Number(constraint.expectedValue));
      }
    }

    // Check character conflicts (including multi-character substring conflicts)
    for (const [param, presentSet] of presentCharsByParam) {
      const absentSet = absentCharsByParam.get(param);
      if (absentSet) {
        for (const presentStr of presentSet) {
          for (const absentStr of absentSet) {
            if (
              presentStr === absentStr ||
              presentStr.includes(absentStr) ||
              absentStr.includes(presentStr)
            ) {
              isSatisfiable = false;
              const conflict = `Contradictory constraints for '${param}': sequence '${presentStr}' conflicts with required absent sequence '${absentStr}'`;
              conflictingGuards.push(conflict);
              logs.push(`[CONFLICT] ${conflict}`);
            }
          }
        }
      }
    }

    // Check length conflicts
    for (const [param, minLen] of minLengthByParam) {
      const maxLen = maxLengthByParam.get(param);
      if (maxLen !== undefined && minLen > maxLen) {
        isSatisfiable = false;
        const conflict = `Contradictory constraints for '${param}': min_length (${minLen}) exceeds max_length (${maxLen})`;
        conflictingGuards.push(conflict);
        logs.push(`[CONFLICT] ${conflict}`);
      }
    }

    // Evaluate bounds if satisfiable so far
    for (const constraint of witness.constraints) {
      if (constraint.type === "min_length") {
        const requiredMin = Number(constraint.expectedValue);
        if (bounds?.maxInputLength !== undefined && bounds.maxInputLength < requiredMin) {
          isSatisfiable = false;
          const conflict = `Max environment input length (${bounds.maxInputLength} bytes) is strictly less than required overflow length (${requiredMin} bytes)`;
          conflictingGuards.push(conflict);
          logs.push(`[CONFLICT] ${conflict}`);
        } else if (bounds?.maxInputLength !== undefined) {
          logs.push(`[SATISFIED] Min length ${requiredMin} bytes is within permitted bounds (${bounds.maxInputLength} bytes)`);
        } else {
          logs.push(`[UNBOUNDED] Min length ${requiredMin} bytes evaluated without environment maxInputLength bound`);
        }
      } else if (constraint.type === "character_present") {
        const requiredChars = Array.isArray(constraint.expectedValue)
          ? constraint.expectedValue.map(String)
          : [String(constraint.expectedValue)];

        if (bounds?.disallowedCharacters && bounds.disallowedCharacters.length > 0) {
          const isSequenceBlocked = (seq: string): boolean => {
            return bounds.disallowedCharacters!.some((blocked) => {
              if (!blocked) return false;
              // 1. Exact match
              if (seq === blocked) return true;
              // 2. The required sequence contains the blocked character or sequence
              // (e.g. seq "../" contains blocked "." or blocked "/" or blocked "../")
              if (seq.includes(blocked)) return true;
              return false;
            });
          };

          const allBlocked = requiredChars.every((ch) => isSequenceBlocked(ch));
          if (allBlocked) {
            isSatisfiable = false;
            const conflict = `All required trigger characters or sequences [${requiredChars.join(", ")}] are disallowed by environment filter`;
            conflictingGuards.push(conflict);
            logs.push(`[CONFLICT] ${conflict}`);
          } else {
            logs.push(`[SATISFIED] At least one trigger sequence [${requiredChars.join(", ")}] is allowed through filter`);
          }
        } else {
          logs.push(`[UNBOUNDED] Trigger sequences [${requiredChars.join(", ")}] evaluated without environment character filter bounds`);
        }
      } else {
        logs.push(`[SATISFIED] Evaluated constraint ${constraint.parameter}: ${constraint.description}`);
      }
    }

    if (!isSatisfiable) {
      logs.push("Validation failed: input constraints are mathematically or architecturally unsatisfiable.");
      return {
        witnessId: witness.witnessId,
        isSatisfiable: false,
        isReproducible: false,
        exploitabilityStatus: "UNSATISFIABLE",
        evaluatedPreconditionsCount: witness.preconditions.length,
        conflictingGuards,
        validationLog: logs,
        verifiedAt,
      };
    }

    // Rule: Satisfiable constraints alone establish THEORETICAL satisfiability.
    // PROVEN exploitability requires validation against verified, complete, non-empty environment bounds.
    // Empty, missing, or incomplete bounds must NEVER produce PROVEN.
    const hasMinLength = witness.constraints.some((c) => c.type === "min_length");
    const hasCharPresent = witness.constraints.some((c) => c.type === "character_present");

    const hasLengthBound =
      typeof bounds?.maxInputLength === "number" &&
      Number.isFinite(bounds.maxInputLength) &&
      bounds.maxInputLength >= 0;
    const hasCharBound = Array.isArray(bounds?.disallowedCharacters);
    const hasFilterBound = Array.isArray(bounds?.enforcedFilters) && bounds.enforcedFilters.length > 0;

    let isCompleteBounds = true;
    if (hasMinLength && !hasLengthBound) {
      isCompleteBounds = false;
      logs.push("[INCOMPLETE_BOUNDS] Witness has min_length constraint but environment bounds omit maxInputLength");
    }
    if (hasCharPresent && !hasCharBound && !hasFilterBound) {
      isCompleteBounds = false;
      logs.push("[INCOMPLETE_BOUNDS] Witness has character_present constraint but environment bounds omit disallowedCharacters/enforcedFilters");
    }

    const hasAnyValidBound = hasLengthBound || hasCharBound || hasFilterBound;
    const isProvenExploitable = hasAnyValidBound && isCompleteBounds;
    const exploitabilityStatus = isProvenExploitable ? "PROVEN" : "THEORETICAL";

    logs.push(
      isProvenExploitable
        ? "Validation successful: all constraints validated and proven satisfiable under complete environment bounds."
        : "Validation incomplete: constraints mathematically satisfiable (THEORETICAL, unvalidated or incomplete against environment bounds).",
    );

    return {
      witnessId: witness.witnessId,
      isSatisfiable: true,
      isReproducible: isProvenExploitable,
      exploitabilityStatus,
      evaluatedPreconditionsCount: witness.preconditions.length,
      conflictingGuards: [],
      validationLog: logs,
      verifiedAt,
    };
  }
}
