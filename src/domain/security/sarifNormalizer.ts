import { err, ok, type Result } from "../result.js";
import type { AssetRecord } from "./asset.js";
import {
  cweIdPattern,
  type CweId,
  type SecuritySeverityLevel,
} from "./classification.js";
import {
  computeFindingId,
  type FindingLocation,
  type SecurityFinding,
} from "./finding.js";

export interface NormalizationError {
  readonly code: "INVALID_SARIF" | "EMPTY_RUNS" | "PARSE_FAILURE";
  readonly message: string;
}

interface SarifRegion {
  startLine?: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
}

interface SarifLocation {
  physicalLocation?: {
    artifactLocation?: {
      uri?: string;
    };
    region?: SarifRegion;
  };
}

interface SarifRule {
  id: string;
  name?: string;
  shortDescription?: { text?: string };
  fullDescription?: { text?: string };
  help?: { text?: string };
  properties?: {
    cwe?: string | string[];
    owasp?: string | string[];
    "security-severity"?: string | number;
  };
}

interface SarifResult {
  ruleId?: string;
  message?: { text?: string };
  level?: "error" | "warning" | "note" | "none";
  locations?: SarifLocation[];
}

interface SarifRun {
  tool?: {
    driver?: {
      name?: string;
      version?: string;
      rules?: SarifRule[];
    };
  };
  results?: SarifResult[];
}

interface SarifLog {
  version?: string;
  runs?: SarifRun[];
}

/**
 * Extract CWE IDs from strings like "CWE-89: SQL Injection" or "CWE-79".
 */
const extractCweIds = (cweInput: unknown): CweId[] => {
  if (!cweInput) return [];
  const rawList = Array.isArray(cweInput) ? cweInput : [cweInput];
  const results: CweId[] = [];

  for (const item of rawList) {
    if (typeof item === "string") {
      const match = cweIdPattern.exec(item) ?? /CWE-\d+/u.exec(item);
      if (match?.[0]) {
        results.push(match[0] as CweId);
      }
    }
  }

  return results;
};

/**
 * Map SARIF level or security-severity score to SecuritySeverityLevel.
 */
const mapSarifSeverity = (
  level?: string,
  securitySeverity?: string | number,
): SecuritySeverityLevel => {
  if (securitySeverity !== undefined) {
    const num =
      typeof securitySeverity === "number"
        ? securitySeverity
        : parseFloat(securitySeverity);
    if (!isNaN(num)) {
      if (num >= 9.0) return "CRITICAL";
      if (num >= 7.0) return "HIGH";
      if (num >= 4.0) return "MEDIUM";
      if (num > 0.0) return "LOW";
      return "INFORMATIONAL";
    }
  }

  switch (level) {
    case "error":
      return "HIGH";
    case "warning":
      return "MEDIUM";
    case "note":
      return "LOW";
    default:
      return "INFORMATIONAL";
  }
};

/**
 * Normalize a standard SARIF v2.1.0 JSON object into SecurityFinding records.
 */
export const normalizeSarif = (
  sarif: unknown,
  asset: AssetRecord,
  now?: string,
): Result<SecurityFinding[], NormalizationError> => {
  if (!sarif || typeof sarif !== "object") {
    return err({
      code: "INVALID_SARIF",
      message: "Provided SARIF input is not a valid JSON object.",
    });
  }

  const log = sarif as SarifLog;
  if (!log.runs || !Array.isArray(log.runs) || log.runs.length === 0) {
    return err({
      code: "EMPTY_RUNS",
      message: "SARIF log contains no valid 'runs' arrays.",
    });
  }

  const timestamp = now ?? new Date().toISOString();
  const findings: SecurityFinding[] = [];

  for (const run of log.runs) {
    const toolName = run.tool?.driver?.name ?? "Static Analysis Tool";
    const rulesMap = new Map<string, SarifRule>();

    if (run.tool?.driver?.rules && Array.isArray(run.tool.driver.rules)) {
      for (const rule of run.tool.driver.rules) {
        if (rule.id) {
          rulesMap.set(rule.id, rule);
        }
      }
    }

    if (!run.results || !Array.isArray(run.results)) {
      continue;
    }

    for (const result of run.results) {
      const ruleId = result.ruleId ?? "unknown_rule";
      const rule = rulesMap.get(ruleId);

      const ruleName =
        rule?.shortDescription?.text ??
        rule?.name ??
        ruleId.replace(/^rules\./u, "");

      const description =
        result.message?.text ??
        rule?.fullDescription?.text ??
        "Security issue detected by static analysis.";

      const rootCause =
        rule?.fullDescription?.text ??
        rule?.help?.text ??
        `Vulnerability flagged by ${toolName} rule '${ruleId}'.`;

      const primaryLocation = result.locations?.[0]?.physicalLocation;
      const filePath = primaryLocation?.artifactLocation?.uri ?? null;
      const region = primaryLocation?.region;

      const location: FindingLocation = {
        file: filePath,
        function: null,
        line: region?.startLine ?? null,
        column: region?.startColumn ?? null,
        end_line: region?.endLine ?? null,
        module: null,
        component: null,
        address: null,
        offset: null,
      };

      const cweList = extractCweIds(rule?.properties?.cwe);
      const owaspList = rule?.properties?.owasp
        ? Array.isArray(rule.properties.owasp)
          ? rule.properties.owasp
          : [rule.properties.owasp]
        : [];

      const severityLevel = mapSarifSeverity(
        result.level,
        rule?.properties?.["security-severity"],
      );

      const findingId = computeFindingId({
        asset_id: asset.id,
        name: ruleName,
        location,
        root_cause: rootCause,
      });

      findings.push({
        id: findingId,
        name: ruleName,
        affected_asset: {
          id: asset.id,
          name: asset.name,
          type: asset.type,
        },
        location,
        technical_description: description,
        root_cause: rootCause,
        evidence_ids: [],
        reproduction_steps: filePath
          ? [`Inspect file '${filePath}' at line ${location.line ?? 1}.`]
          : [],
        impact: {
          description: description,
          attack_prerequisites: [],
          exploitability: "UNKNOWN",
        },
        severity: {
          level: severityLevel,
          cvss_vector: null,
          cvss_score:
            rule?.properties?.["security-severity"] !== undefined
              ? Number(rule.properties["security-severity"])
              : null,
          justification: `Derived from ${toolName} diagnostic level '${result.level ?? "none"}'`,
        },
        confidence: {
          level: "MEDIUM",
          false_positive_considerations: [
            "Static analysis pattern may not account for sanitization in outer callers.",
          ],
          verification_method: null,
        },
        remediation: {
          description:
            rule?.help?.text ??
            "Review flagged code and implement input validation/sanitization.",
          code_diff: null,
          config_example: null,
          priority: severityLevel === "CRITICAL" ? "IMMEDIATE" : "MEDIUM_TERM",
          validation_procedure: `Re-run ${toolName} scan on file.`,
        },
        classification: {
          cve: [],
          cwe: cweList,
          capec: [],
          mitre_attack: [],
          owasp: owaspList,
        },
        verification_status: "UNVERIFIED",
        provenance: {
          discovered_by: toolName,
          discovered_at: timestamp,
          verified_by: null,
          verified_at: null,
        },
      });
    }
  }

  return ok(findings);
};
