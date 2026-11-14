import { describe, expect, it } from "vitest";
import { computeAssetId } from "./asset.js";
import { normalizeSarif } from "./sarifNormalizer.js";

describe("SARIF Normalizer", () => {
  const asset = {
    id: computeAssetId({
      name: "sample_service",
      type: "source_repository",
    }),
    name: "sample_service",
    type: "source_repository" as const,
    path: "/home/user/project",
    digest: null,
    architecture: null,
    version: null,
    environment: null,
    tags: [],
    metadata: {},
  };

  it("rejects non-object or invalid SARIF inputs", () => {
    expect(normalizeSarif(null, asset).ok).toBe(false);
    expect(normalizeSarif("invalid_json", asset).ok).toBe(false);
    expect(normalizeSarif({ version: "2.1.0", runs: [] }, asset).ok).toBe(false);
  });

  it("normalizes Semgrep-style SARIF log into SecurityFinding records", () => {
    const semgrepSarif = {
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Semgrep OSS",
              version: "1.50.0",
              rules: [
                {
                  id: "python.flask.security.injection.raw-sql",
                  shortDescription: { text: "Raw SQL query injection" },
                  fullDescription: {
                    text: "Untrusted user input concatenated directly into database query string.",
                  },
                  help: {
                    text: "Use parameterized queries or ORM models instead of string concatenation.",
                  },
                  properties: {
                    cwe: ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
                    owasp: ["A03:2021-Injection"],
                    "security-severity": "8.8",
                  },
                },
              ],
            },
          },
          results: [
            {
              ruleId: "python.flask.security.injection.raw-sql",
              message: {
                text: "Query string contains unsanitized user parameter 'request.args.get(\"id\")'.",
              },
              level: "error",
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: {
                      uri: "app/views/users.py",
                    },
                    region: {
                      startLine: 45,
                      startColumn: 12,
                      endLine: 45,
                      endColumn: 68,
                    },
                  },
                },
              ],
            },
          ],
        },
      ],
    };

    const result = normalizeSarif(semgrepSarif, asset, "2026-11-05T12:00:00.000Z");
    expect(result.ok).toBe(true);

    if (result.ok) {
      expect(result.value).toHaveLength(1);
      const finding = result.value[0];
      expect(finding).toBeDefined();
      if (finding) {
        expect(finding.name).toBe("Raw SQL query injection");
        expect(finding.affected_asset.name).toBe("sample_service");
        expect(finding.location.file).toBe("app/views/users.py");
        expect(finding.location.line).toBe(45);
        expect(finding.severity.level).toBe("HIGH"); // 8.8 -> HIGH
        expect(finding.severity.cvss_score).toBe(8.8);
        expect(finding.classification.cwe).toEqual(["CWE-89"]);
        expect(finding.classification.owasp).toEqual(["A03:2021-Injection"]);
        expect(finding.remediation.description).toContain("parameterized queries");
        expect(finding.provenance.discovered_by).toBe("Semgrep OSS");
      }
    }
  });

  it("handles SARIF results with missing optional fields gracefully", () => {
    const minimalSarif = {
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Generic Linter",
            },
          },
          results: [
            {
              ruleId: "custom_rule",
              level: "warning",
            },
          ],
        },
      ],
    };

    const result = normalizeSarif(minimalSarif, asset);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toHaveLength(1);
      const finding = result.value[0];
      expect(finding).toBeDefined();
      if (finding) {
        expect(finding.name).toBe("custom_rule");
        expect(finding.severity.level).toBe("MEDIUM");
        expect(finding.location.file).toBeNull();
      }
    }
  });
});

