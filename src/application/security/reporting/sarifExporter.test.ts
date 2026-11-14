import { describe, expect, it } from "vitest";
import type { SecurityFinding } from "../../../domain/security/finding.js";
import type { AssetId } from "../../../domain/security/asset.js";
import { SarifExporter } from "./SarifExporter.js";

describe("SarifExporter 2.1.0 Generation & Compliance", () => {
  const dummyFinding: SecurityFinding = {
    id: "fnd_test_0000000000000000000000000000000000000000000000000000000000000001",
    name: "Buffer Overflow via strcpy",
    affected_asset: {
      id: "ast_binary_0000000000000000000000000000000000000000000000000000000000000001" as AssetId,
      name: "router_daemon",
      type: "compiled_binary",
    },
    location: {
      file: "usr/sbin/router_daemon",
      function: "parse_header",
      line: 42,
      column: 8,
      end_line: 42,
      module: "router_daemon",
      component: "compiled_binary",
      address: "0x00010420",
      offset: 0x420,
    },
    technical_description: "Unbounded buffer copy using strcpy in parse_header",
    root_cause: "strcpy lacks bounds check",
    evidence_ids: ["ev_strcpy_01"],
    reproduction_steps: ["Send payload > 256 bytes"],
    impact: {
      description: "Arbitrary code execution",
      attack_prerequisites: ["Network access"],
      exploitability: "PROVEN",
    },
    severity: {
      level: "CRITICAL",
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      cvss_score: 10.0,
      justification: "Remote unauthenticated code execution",
    },
    confidence: {
      level: "CONFIRMED",
      false_positive_considerations: [],
      verification_method: "L5 Witness verified",
    },
    remediation: {
      description: "Replace with strlcpy",
      code_diff: null,
      config_example: null,
      priority: "IMMEDIATE",
      validation_procedure: "Recompile and test",
    },
    classification: {
      cve: [],
      cwe: ["CWE-120" as any],
      capec: [],
      mitre_attack: [],
      owasp: [],
    },
    verification_status: "VERIFIED",
    provenance: {
      discovered_by: "BinaryAnalysisWorker",
      discovered_at: "2026-11-06T12:00:00Z",
      verified_by: "AdjudicationEngine",
      verified_at: "2026-11-06T12:05:00Z",
    },
  };

  it("exports valid SARIF 2.1.0 document matching schema specification", () => {
    const sarif = SarifExporter.exportFindings([dummyFinding]);

    expect(sarif.$schema).toBe(SarifExporter.SARIF_SCHEMA);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs.length).toBe(1);

    const run = sarif.runs[0]!;
    expect(run.tool.driver.name).toBe("REA Security Platform");
    expect(run.tool.driver.version).toBe("6.7.0");

    // Verify Rule
    expect(run.tool.driver.rules.length).toBe(1);
    expect(run.tool.driver.rules[0]!.id).toBe("REA-CWE-120");
    expect(run.tool.driver.rules[0]!.properties?.cwe).toContain("CWE-120");

    // Verify Result
    expect(run.results.length).toBe(1);
    const result = run.results[0]!;
    expect(result.ruleId).toBe("REA-CWE-120");
    expect(result.level).toBe("error");
    expect(result.message.text).toBe(dummyFinding.technical_description);

    // Verify Physical & Logical Locations
    const phys = result.locations[0]!.physicalLocation;
    expect(phys.artifactLocation.uri).toBe("usr/sbin/router_daemon");
    expect(phys.region?.startLine).toBe(42);
    expect(phys.address).toBe(0x00010420);

    const log = result.locations[0]!.logicalLocations![0]!;
    expect(log.name).toBe("parse_header");
    expect(log.kind).toBe("function");

    // Verify properties
    expect(result.properties.finding_id).toBe(dummyFinding.id);
    expect(result.properties.verification_status).toBe("VERIFIED");
    expect(result.properties.cvss_score).toBe(10.0);
    expect(result.properties.cvss_vector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  });

  it("passes self-validation against SARIF structural constraints", () => {
    const sarif = SarifExporter.exportFindings([dummyFinding]);
    const valRes = SarifExporter.validate(sarif);
    expect(valRes.ok).toBe(true);
  });

  it("rejects malformed SARIF structures during validation", () => {
    const invalid1 = { version: "2.0.0" }; // Wrong version
    expect(SarifExporter.validate(invalid1).ok).toBe(false);

    const invalid2 = {
      $schema: SarifExporter.SARIF_SCHEMA,
      version: "2.1.0",
      runs: [], // Empty runs
    };
    expect(SarifExporter.validate(invalid2).ok).toBe(false);
  });
});

