import { describe, expect, it } from "vitest";
import { computeAssetId } from "../../../domain/security/asset.js";
import type { ProviderProcessSnapshot } from "../../../process/ProviderProcess.js";
import { runSemgrepScan } from "./semgrepAdapter.js";

describe("Semgrep SAST Adapter", () => {
  const asset = {
    id: computeAssetId({
      name: "sample_repo",
      type: "source_repository",
    }),
    name: "sample_repo",
    type: "source_repository" as const,
    path: "/repo",
    digest: null,
    architecture: null,
    version: null,
    environment: null,
    tags: [],
    metadata: {},
  };

  const sampleSarifOutput = JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Semgrep OSS",
            rules: [
              {
                id: "javascript.express.security.audit.xss",
                shortDescription: { text: "Cross-site Scripting (XSS)" },
                fullDescription: { text: "Unescaped output sent to response." },
                properties: {
                  cwe: ["CWE-79"],
                  owasp: ["A03:2021-Injection"],
                  "security-severity": "7.5",
                },
              },
            ],
          },
        },
        results: [
          {
            ruleId: "javascript.express.security.audit.xss",
            message: { text: "Direct response.send of user input." },
            level: "error",
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "server/routes/home.js" },
                  region: { startLine: 18, startColumn: 5 },
                },
              },
            ],
          },
        ],
      },
    ],
  });

  it("successfully parses SARIF stdout into SecurityFindings", async () => {
    const mockRunner = async (): Promise<ProviderProcessSnapshot> => ({
      stdout: {
        text: sampleSarifOutput,
        bytes: sampleSarifOutput.length,
        observedBytes: sampleSarifOutput.length,
      },
      stderr: {
        text: "",
        bytes: 0,
        observedBytes: 0,
      },
      exitCode: 1, // Findings present
      signal: null,
    });

    const result = await runSemgrepScan({
      targets: ["src/"],
      asset,
      commandRunner: mockRunner,
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.findings).toHaveLength(1);
      const finding = result.value.findings[0];
      expect(finding).toBeDefined();
      if (finding) {
        expect(finding.name).toBe("Cross-site Scripting (XSS)");
        expect(finding.location.file).toBe("server/routes/home.js");
        expect(finding.location.line).toBe(18);
        expect(finding.severity.level).toBe("HIGH");
        expect(finding.classification.cwe).toEqual(["CWE-79"]);
      }
    }
  });

  it("handles missing semgrep binary gracefully (SEMGREP_NOT_INSTALLED)", async () => {
    const mockRunner = async (): Promise<ProviderProcessSnapshot> => {
      const err = new Error("spawn semgrep ENOENT");
      throw err;
    };

    const result = await runSemgrepScan({
      targets: ["src/"],
      asset,
      commandRunner: mockRunner,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("SEMGREP_NOT_INSTALLED");
      expect(result.error.message).toContain("pip install semgrep");
    }
  });

  it("handles timeout correctly (SEMGREP_TIMEOUT)", async () => {
    const mockRunner = async (): Promise<ProviderProcessSnapshot> => {
      throw new Error("Command timeout elapsed after 5000ms");
    };

    const result = await runSemgrepScan({
      targets: ["src/"],
      asset,
      timeoutMs: 5000,
      commandRunner: mockRunner,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("SEMGREP_TIMEOUT");
    }
  });

  it("handles empty findings (clean scan)", async () => {
    const emptySarif = JSON.stringify({
      version: "2.1.0",
      runs: [{ tool: { driver: { name: "Semgrep" } }, results: [] }],
    });

    const mockRunner = async (): Promise<ProviderProcessSnapshot> => ({
      stdout: { text: emptySarif, bytes: emptySarif.length, observedBytes: emptySarif.length },
      stderr: { text: "", bytes: 0, observedBytes: 0 },
      exitCode: 0,
      signal: null,
    });

    const result = await runSemgrepScan({
      targets: ["src/"],
      asset,
      commandRunner: mockRunner,
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.findings).toHaveLength(0);
    }
  });
});
