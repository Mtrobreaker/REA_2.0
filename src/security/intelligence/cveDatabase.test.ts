import { describe, expect, it } from "vitest";
import { computeAssetId } from "../../domain/security/asset.js";
import type { CveId } from "../../domain/security/classification.js";
import { computeFindingId, type SecurityFinding } from "../../domain/security/finding.js";
import { CveDatabase, defaultCveDatabase } from "./cveDatabase.js";

describe("CVE Threat Intelligence Database", () => {
  it("looks up known landmark CVEs with verified CVSS calculations", () => {
    const res = defaultCveDatabase.lookup("CVE-2021-44228");
    expect(res.ok).toBe(true);

    if (res.ok) {
      expect(res.value.cve.title).toContain("Log4Shell");
      expect(res.value.cvss.score).toBe(9.8);
      expect(res.value.cvss.severity).toBe("CRITICAL");
      expect(res.value.cve.cwe_ids).toContain("CWE-502");
    }
  });

  it("handles unknown or malformed CVE lookups", () => {
    expect(defaultCveDatabase.lookup("CVE-1900-0000").ok).toBe(false);
    expect(defaultCveDatabase.lookup("NOT-A-CVE").ok).toBe(false);
  });

  it("queries CVEs by CWE identifier", () => {
    const matches = defaultCveDatabase.queryByCwe("CWE-119");
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.some((m) => m.id === "CVE-2017-0144")).toBe(true);
  });

  it("enriches a candidate SecurityFinding with CVE facts and CVSS scores", () => {
    const assetId = computeAssetId({ name: "app", type: "source_repository" });
    const location = {
      file: "pom.xml",
      function: null,
      line: 10,
      column: null,
      end_line: null,
      module: null,
      component: null,
      address: null,
      offset: null,
    };

    const rawFinding: SecurityFinding = {
      id: computeFindingId({
        asset_id: assetId,
        name: "Vulnerable Log4j",
        location,
        root_cause: "Old dependency",
      }),
      name: "Vulnerable Log4j",
      affected_asset: { id: assetId, name: "app", type: "source_repository" },
      location,
      technical_description: "Old log4j found",
      root_cause: "Old dependency",
      evidence_ids: [],
      reproduction_steps: [],
      impact: { description: "RCE", attack_prerequisites: [], exploitability: "PROVEN" },
      severity: { level: "MEDIUM", cvss_vector: null, cvss_score: null, justification: "" },
      confidence: { level: "CONFIRMED", false_positive_considerations: [], verification_method: null },
      remediation: { description: "Upgrade to 2.17.1", code_diff: null, config_example: null, priority: "IMMEDIATE", validation_procedure: "" },
      classification: {
        cve: ["CVE-2021-44228" as CveId],
        cwe: [],
        capec: [],
        mitre_attack: [],
        owasp: [],
      },
      verification_status: "VERIFIED",
      provenance: { discovered_by: "test", discovered_at: "2026-11-05T12:00:00.000Z", verified_by: null, verified_at: null },
    };

    const enriched = defaultCveDatabase.enrichFinding(rawFinding);
    expect(enriched.severity.cvss_score).toBe(9.8);
    expect(enriched.severity.level).toBe("CRITICAL");
    expect(enriched.severity.cvss_vector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(enriched.classification.cwe).toContain("CWE-502");
  });
});
