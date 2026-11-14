import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { SecurityFinding } from "../../../domain/security/finding.js";
import type { FindingRecord } from "../../../domain/security/blackboard/types.js";
import { err, ok, type Result } from "../../../domain/result.js";

export interface SarifExportOptions {
  readonly toolName?: string;
  readonly toolVersion?: string;
  readonly informationUri?: string;
  readonly assessmentId?: AssessmentId;
}

export interface SarifRegion {
  readonly startLine?: number | undefined;
  readonly startColumn?: number | undefined;
  readonly endLine?: number | undefined;
  readonly endColumn?: number | undefined;
}

export interface SarifArtifactLocation {
  readonly uri: string;
  readonly uriBaseId?: string | undefined;
}

export interface SarifPhysicalLocation {
  readonly artifactLocation: SarifArtifactLocation;
  readonly region?: SarifRegion | undefined;
  readonly address?: number | undefined;
}

export interface SarifLogicalLocation {
  readonly name: string;
  readonly kind: string;
}

export interface SarifLocation {
  readonly physicalLocation: SarifPhysicalLocation;
  readonly logicalLocations?: readonly SarifLogicalLocation[] | undefined;
}

export interface SarifRule {
  readonly id: string;
  readonly name: string;
  readonly shortDescription: { readonly text: string };
  readonly fullDescription: { readonly text: string };
  readonly defaultConfiguration?: { readonly level: "error" | "warning" | "note" } | undefined;
  readonly help?: { readonly text: string } | undefined;
  readonly properties?: {
    readonly tags?: readonly string[] | undefined;
    readonly cwe?: readonly string[] | undefined;
  } | undefined;
}

export interface SarifResult {
  readonly ruleId: string;
  readonly ruleIndex?: number | undefined;
  readonly level: "error" | "warning" | "note";
  readonly message: { readonly text: string };
  readonly locations: readonly SarifLocation[];
  readonly properties: {
    readonly finding_id: string;
    readonly verification_status: string;
    readonly confidence_level: string;
    readonly evidence_ids: readonly string[];
    readonly asset_id: string;
    readonly cwe: readonly string[];
    readonly cvss_score?: number | null | undefined;
    readonly cvss_vector?: string | null | undefined;
    readonly remediation_priority: string;
  };
}

export interface SarifRun {
  readonly tool: {
    readonly driver: {
      readonly name: string;
      readonly version: string;
      readonly informationUri: string;
      readonly rules: readonly SarifRule[];
    };
  };
  readonly invocations?: readonly [
    {
      readonly executionSuccessful: boolean;
      readonly endTimeUtc: string;
    },
  ];
  readonly results: readonly SarifResult[];
}

export interface SarifDocument {
  readonly $schema: string;
  readonly version: "2.1.0";
  readonly runs: readonly SarifRun[];
}

export class SarifExporter {
  public static readonly SARIF_SCHEMA =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
  public static readonly SARIF_VERSION = "2.1.0" as const;

  /**
   * Normalize either a full SecurityFinding or a Blackboard FindingRecord into a SecurityFinding.
   */
  public static normalizeToSecurityFinding(
    input: SecurityFinding | FindingRecord,
  ): SecurityFinding {
    if ("affected_asset" in input && "classification" in input) {
      return input as SecurityFinding;
    }
    const r = input as FindingRecord;
    return {
      id: r.id,
      name: r.title,
      affected_asset: {
        id: r.asset_id,
        name: r.location.module ?? r.asset_id,
        type: (r.location.component as any) ?? "compiled_binary",
      },
      location: r.location,
      technical_description: r.description,
      root_cause: r.description,
      evidence_ids: [...r.evidence_ids],
      reproduction_steps: [],
      impact: {
        description: `Identified issue: ${r.title}`,
        attack_prerequisites: [],
        exploitability: r.state === "VERIFIED" ? "PROVEN" : "THEORETICAL",
      },
      severity: r.severity,
      confidence: r.confidence,
      remediation: r.remediation ?? {
        description: "Remediation pending further analysis",
        code_diff: null,
        config_example: null,
        priority: "MEDIUM_TERM",
        validation_procedure: "",
      },
      classification: {
        cve: [],
        cwe: (r.cwe ?? []) as any,
        capec: [],
        mitre_attack: [],
        owasp: [],
      },
      verification_status: r.state as any,
      provenance: {
        discovered_by: "BinaryAnalysisWorker",
        discovered_at: new Date(r.created_at).toISOString(),
        verified_by: null,
        verified_at: null,
      },
    };
  }

  /**
   * Export a collection of SecurityFinding or FindingRecord items into a standard SARIF 2.1.0 JSON document.
   */
  public static exportFindings(
    findings: readonly (SecurityFinding | FindingRecord)[],
    options?: SarifExportOptions,
  ): SarifDocument {
    const toolName = options?.toolName ?? "REA Security Platform";
    const toolVersion = options?.toolVersion ?? "6.7.0";
    const informationUri =
      options?.informationUri ?? "https://github.com/google/rea";

    const ruleMap = new Map<string, SarifRule>();
    const sarifResults: SarifResult[] = [];

    const normalizedFindings = findings.map((f) => this.normalizeToSecurityFinding(f));

    for (const finding of normalizedFindings) {
      // 1. Derive or register Rule
      const ruleId = this.deriveRuleId(finding);
      if (!ruleMap.has(ruleId)) {
        ruleMap.set(ruleId, {
          id: ruleId,
          name: finding.name.replace(/[^a-zA-Z0-9]/gu, ""),
          shortDescription: { text: finding.name },
          fullDescription: { text: finding.technical_description },
          defaultConfiguration: {
            level: this.mapSeverityToLevel(finding.severity.level),
          },
          help: { text: finding.remediation.description },
          properties: {
            tags: ["security", "vulnerability"],
            cwe: finding.classification.cwe as string[],
          },
        });
      }

      const ruleIndex = Array.from(ruleMap.keys()).indexOf(ruleId);

      // 2. Map physical and logical locations
      const uri = finding.location.file || finding.affected_asset.name;
      const physicalLocation: SarifPhysicalLocation = {
        artifactLocation: {
          uri: uri.replace(/\\/gu, "/"),
          uriBaseId: "%SRCROOT%",
        },
        ...(finding.location.line !== null
          ? {
              region: {
                startLine: finding.location.line,
                startColumn: finding.location.column ?? 1,
                endLine: finding.location.end_line ?? finding.location.line,
              },
            }
          : {}),
        ...(finding.location.address !== null
          ? {
              address: parseInt(finding.location.address, 16) || undefined,
            }
          : {}),
      };

      const logicalLocations: SarifLogicalLocation[] = finding.location.function
        ? [
            {
              name: finding.location.function,
              kind: "function",
            },
          ]
        : [];

      // 3. Map CVSS score (DO NOT invent scores: only include if explicitly scored with vector)
      const hasValidCvss =
        finding.severity.cvss_score !== null &&
        finding.severity.cvss_vector !== null &&
        finding.severity.cvss_vector.length > 0;

      sarifResults.push({
        ruleId,
        ruleIndex: ruleIndex >= 0 ? ruleIndex : undefined,
        level: this.mapSeverityToLevel(finding.severity.level),
        message: { text: finding.technical_description },
        locations: [
          {
            physicalLocation,
            ...(logicalLocations.length > 0 ? { logicalLocations } : {}),
          },
        ],
        properties: {
          finding_id: finding.id,
          verification_status: finding.verification_status,
          confidence_level: finding.confidence.level,
          evidence_ids: finding.evidence_ids,
          asset_id: finding.affected_asset.id,
          cwe: finding.classification.cwe as string[],
          ...(hasValidCvss
            ? {
                cvss_score: finding.severity.cvss_score,
                cvss_vector: finding.severity.cvss_vector,
              }
            : {}),
          remediation_priority: finding.remediation.priority,
        },
      });
    }

    const run: SarifRun = {
      tool: {
        driver: {
          name: toolName,
          version: toolVersion,
          informationUri,
          rules: Array.from(ruleMap.values()),
        },
      },
      invocations: [
        {
          executionSuccessful: true,
          endTimeUtc: new Date().toISOString(),
        },
      ],
      results: sarifResults,
    };

    return {
      $schema: this.SARIF_SCHEMA,
      version: this.SARIF_VERSION,
      runs: [run],
    };
  }

  /**
   * Validate a generated SARIF document against core structural invariants.
   */
  public static validate(doc: unknown): Result<SarifDocument, string> {
    if (!doc || typeof doc !== "object") {
      return err("SARIF document must be a non-null object");
    }

    const s = doc as Partial<SarifDocument>;
    if (s.$schema !== this.SARIF_SCHEMA) {
      return err(`Invalid SARIF $schema: expected ${this.SARIF_SCHEMA}, got ${s.$schema}`);
    }

    if (s.version !== "2.1.0") {
      return err(`Invalid SARIF version: expected 2.1.0, got ${s.version}`);
    }

    if (!Array.isArray(s.runs) || s.runs.length === 0) {
      return err("SARIF document must contain at least one run in 'runs'");
    }

    for (const run of s.runs) {
      if (!run.tool?.driver?.name) {
        return err("SARIF run missing tool.driver.name");
      }
      if (!run.tool?.driver?.version) {
        return err("SARIF run missing tool.driver.version");
      }
      if (!Array.isArray(run.results)) {
        return err("SARIF run missing 'results' array");
      }

      for (const res of run.results) {
        if (!res.ruleId) {
          return err("SARIF result missing 'ruleId'");
        }
        if (!res.message?.text) {
          return err("SARIF result missing 'message.text'");
        }
        if (!Array.isArray(res.locations) || res.locations.length === 0) {
          return err("SARIF result missing 'locations'");
        }
        const loc = res.locations[0]!;
        if (!loc.physicalLocation?.artifactLocation?.uri) {
          return err("SARIF location missing 'physicalLocation.artifactLocation.uri'");
        }
      }
    }

    return ok(doc as SarifDocument);
  }

  private static deriveRuleId(finding: SecurityFinding): string {
    const cweFirst = finding.classification.cwe[0];
    if (cweFirst) {
      return `REA-${cweFirst}`;
    }
    return `REA-RULE-${finding.name.toUpperCase().replace(/[^A-Z0-9]/gu, "-").slice(0, 24)}`;
  }

  private static mapSeverityToLevel(
    severity: SecurityFinding["severity"]["level"],
  ): "error" | "warning" | "note" {
    switch (severity) {
      case "CRITICAL":
      case "HIGH":
        return "error";
      case "MEDIUM":
        return "warning";
      case "LOW":
      case "INFORMATIONAL":
        return "note";
    }
  }
}
