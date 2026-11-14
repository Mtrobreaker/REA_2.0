import { describe, expect, it } from "vitest";
import { computeAssetId } from "../../../domain/security/asset.js";
import type { ProviderProcessSnapshot } from "../../../process/ProviderProcess.js";
import { runTrivyScan } from "./trivyAdapter.js";

describe("Trivy Vulnerability & Container Adapter", () => {
  const asset = {
    id: computeAssetId({
      name: "node_container:latest",
      type: "source_repository",
    }),
    name: "node_container:latest",
    type: "source_repository" as const,
    path: "/docker/node_container",
    digest: null,
    architecture: null,
    version: "18-alpine",
    environment: null,
    tags: [],
    metadata: {},
  };

  const sampleTrivySarif = JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Trivy",
            rules: [
              {
                id: "CVE-2023-44487",
                shortDescription: { text: "HTTP/2 Rapid Reset Attack" },
                fullDescription: {
                  text: "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly.",
                },
                properties: {
                  cwe: ["CWE-400"],
                  "security-severity": "7.5",
                },
              },
            ],
          },
        },
        results: [
          {
            ruleId: "CVE-2023-44487",
            message: {
              text: "Package: nghttp2 (1.51.0-r0), Installed: 1.51.0-r0, Fixed: 1.51.0-r1",
            },
            level: "error",
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "lib/libnghttp2.so.14" },
                },
              },
            ],
          },
        ],
      },
    ],
  });

  it("parses Trivy SARIF scan and produces SecurityFindings", async () => {
    const mockRunner = async (): Promise<ProviderProcessSnapshot> => ({
      stdout: {
        text: sampleTrivySarif,
        bytes: sampleTrivySarif.length,
        observedBytes: sampleTrivySarif.length,
      },
      stderr: { text: "", bytes: 0, observedBytes: 0 },
      exitCode: 0,
      signal: null,
    });

    const result = await runTrivyScan({
      target: "/docker/node_container",
      mode: "fs",
      asset,
      commandRunner: mockRunner,
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.findings).toHaveLength(1);
      const finding = result.value.findings[0];
      expect(finding).toBeDefined();
      if (finding) {
        expect(finding.name).toBe("HTTP/2 Rapid Reset Attack");
        expect(finding.severity.level).toBe("HIGH");
        expect(finding.severity.cvss_score).toBe(7.5);
        expect(finding.classification.cwe).toEqual(["CWE-400"]);
        expect(finding.location.file).toBe("lib/libnghttp2.so.14");
      }
    }
  });

  it("handles missing Trivy binary (TRIVY_NOT_INSTALLED)", async () => {
    const mockRunner = async (): Promise<ProviderProcessSnapshot> => {
      throw new Error("spawn trivy ENOENT");
    };

    const result = await runTrivyScan({
      target: "/docker/node_container",
      asset,
      commandRunner: mockRunner,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("TRIVY_NOT_INSTALLED");
      expect(result.error.message).toContain("brew install trivy");
    }
  });
});

