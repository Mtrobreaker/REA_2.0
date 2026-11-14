import { describe, expect, it } from "vitest";
import type { AssessmentState } from "../../domain/security/assessment.js";
import type { AssetRecord } from "../../domain/security/asset.js";
import type {
  CapecId,
  CveId,
  CweId,
  MitreAttackTechniqueId,
} from "../../domain/security/classification.js";
import type { SecurityFinding } from "../../domain/security/finding.js";
import { SecurityKnowledgeGraph } from "./knowledgeGraph.js";

const sampleAssetA: AssetRecord = {
  id: "ast_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  name: "iot-gateway-firmware",
  type: "firmware_image",
  path: "/firmware.bin",
  digest: null,
  architecture: "ARM",
  version: "1.0.0",
  environment: null,
  tags: ["perimeter", "iot"],
  metadata: {},
};

const sampleAssetB: AssetRecord = {
  id: "ast_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  name: "core-auth-daemon",
  type: "compiled_binary",
  path: "/usr/sbin/auth_daemon",
  digest: null,
  architecture: "x86_64",
  version: "2.1.0",
  environment: null,
  tags: ["backend", "critical"],
  metadata: { crown_jewel: true },
};

const sampleKeyFinding: SecurityFinding = {
  id: "fnd_1111111111111111111111111111111111111111111111111111111111111111",
  name: "Embedded Cryptographic Private Key in Firmware",
  affected_asset: {
    id: sampleAssetA.id,
    name: sampleAssetA.name,
    type: sampleAssetA.type,
  },
  location: {
    file: "/firmware.bin",
    function: null,
    line: null,
    column: null,
    end_line: null,
    module: "secrets",
    component: null,
    address: null,
    offset: 1024,
  },
  technical_description: "Private key embedded in firmware filesystem.",
  root_cause: "Hardcoded key in build.",
  evidence_ids: [],
  reproduction_steps: [],
  impact: {
    description: "Allows authentication bypass.",
    attack_prerequisites: [],
    exploitability: "PROVEN",
  },
  severity: {
    level: "CRITICAL",
    cvss_vector: null,
    cvss_score: 8.8,
    justification: "Auth compromise",
  },
  confidence: {
    level: "CONFIRMED",
    false_positive_considerations: [],
    verification_method: null,
  },
  remediation: {
    description: "Remove key",
    code_diff: null,
    config_example: null,
    priority: "IMMEDIATE",
    validation_procedure: "Check build",
  },
  classification: {
    cve: ["CVE-2023-9999" as CveId],
    cwe: ["CWE-798" as CweId],
    capec: ["CAPEC-37" as CapecId],
    mitre_attack: ["T1552" as MitreAttackTechniqueId],
    owasp: [],
  },
  verification_status: "VERIFIED",
  provenance: {
    discovered_by: "firmware-agent",
    discovered_at: "2026-11-05T12:00:00Z",
    verified_by: null,
    verified_at: null,
  },
};

const sampleNativeFinding: SecurityFinding = {
  id: "fnd_2222222222222222222222222222222222222222222222222222222222222222",
  name: "Insecure Native Function Call: system",
  affected_asset: {
    id: sampleAssetB.id,
    name: sampleAssetB.name,
    type: sampleAssetB.type,
  },
  location: {
    file: "/usr/sbin/auth_daemon",
    function: "system",
    line: null,
    column: null,
    end_line: null,
    module: "symbols",
    component: null,
    address: "0x401020",
    offset: null,
  },
  technical_description: "Binary invokes unvalidated system() call.",
  root_cause: "Direct invocation of system shell.",
  evidence_ids: [],
  reproduction_steps: [],
  impact: {
    description: "Remote code execution.",
    attack_prerequisites: [],
    exploitability: "PROVEN",
  },
  severity: {
    level: "HIGH",
    cvss_vector: null,
    cvss_score: 8.1,
    justification: "Shell injection",
  },
  confidence: {
    level: "CONFIRMED",
    false_positive_considerations: [],
    verification_method: null,
  },
  remediation: {
    description: "Use execve",
    code_diff: null,
    config_example: null,
    priority: "IMMEDIATE",
    validation_procedure: "Check symbols",
  },
  classification: {
    cve: [],
    cwe: ["CWE-78" as CweId],
    capec: ["CAPEC-88" as CapecId],
    mitre_attack: ["T1059" as MitreAttackTechniqueId],
    owasp: [],
  },
  verification_status: "VERIFIED",
  provenance: {
    discovered_by: "binary-agent",
    discovered_at: "2026-11-05T12:00:00Z",
    verified_by: null,
    verified_at: null,
  },
};

const sampleAssessment: AssessmentState = {
  assessment_id: "asm_1111111111111111111111111111111111111111111111111111111111111111",
  objective: {
    title: "Gateway to Core Penetration Audit",
    target_technologies: ["Firmware", "ELF"],
    compliance_frameworks: [],
    focus_areas: [],
    depth: "exhaustive",
  },
  scope: {
    allowed_targets: ["/firmware.bin", "/usr/sbin/auth_daemon"],
    denied_targets: [],
    authorized_by: "Director",
    authorization_reference: "REF",
    valid_until: "2026-12-31T23:59:59Z",
    allow_active_verification: true,
  },
  phase: "completed",
  created_at: "2026-11-05T12:00:00Z",
  updated_at: "2026-11-05T12:00:00Z",
  completed_at: "2026-11-05T12:00:00Z",
  assets: [sampleAssetA, sampleAssetB],
  findings: [sampleKeyFinding, sampleNativeFinding],
  metrics: {
    total_assets: 2,
    total_findings: 2,
    critical_findings: 1,
    high_findings: 1,
    medium_findings: 0,
    low_findings: 0,
    info_findings: 0,
    verified_findings: 2,
  },
};

describe("SecurityKnowledgeGraph & Attack Path Modeling", () => {
  it("constructs heterogeneous property graph with assets, findings, CWEs, CVEs, and ATT&CK techniques", () => {
    const graph = new SecurityKnowledgeGraph(sampleAssessment);

    // Verify Nodes
    expect(graph.nodes.length).toBeGreaterThanOrEqual(6); // 2 assets + 2 findings + CWEs + CVEs + ATT&CK
    expect(graph.getNode(sampleAssetA.id)?.type).toBe("asset");
    expect(graph.getNode(sampleKeyFinding.id)?.type).toBe("finding");
    expect(graph.getNode("CWE-798")?.type).toBe("cwe");
    expect(graph.getNode("CVE-2023-9999")?.type).toBe("cve");
    expect(graph.getNode("T1552")?.type).toBe("mitre_technique");

    // Verify Edges
    expect(graph.edges.length).toBeGreaterThanOrEqual(6);
    expect(
      graph.edges.some((e) => e.relationship === "AFFECTS" && e.source === sampleKeyFinding.id),
    ).toBe(true);
    expect(
      graph.edges.some((e) => e.relationship === "CLASSIFIED_AS_CWE" && e.target === "CWE-798"),
    ).toBe(true);
    expect(
      graph.edges.some((e) => e.relationship === "CORRELATED_WITH_CVE" && e.target === "CVE-2023-9999"),
    ).toBe(true);
  });

  it("identifies multi-hop chained attack paths linking credential exposure to command execution", () => {
    const graph = new SecurityKnowledgeGraph(sampleAssessment);
    const paths = graph.findAttackPaths();

    expect(paths.length).toBeGreaterThanOrEqual(1);
    const chainPath = paths[0]!;

    expect(chainPath.title).toContain("Composite Exploit Chain");
    expect(chainPath.steps).toHaveLength(2);
    expect(chainPath.cumulative_risk).toBeGreaterThanOrEqual(9.0);
    expect(chainPath.overall_severity).toBe("CRITICAL");
    expect(chainPath.narrative).toContain("Multi-hop attack path identified");
  });

  it("computes risk posture verdict for crown jewel assets", () => {
    const graph = new SecurityKnowledgeGraph(sampleAssessment);
    const report = graph.computeCrownJewelRisk(sampleAssessment);

    expect(report.crown_jewel_assets).toHaveLength(1);
    expect(report.crown_jewel_assets[0]!.name).toBe("core-auth-daemon");
    expect(report.reachable_paths.length).toBeGreaterThanOrEqual(1);
    expect(report.posture_verdict).toBe("COMPROMISED");
  });
});

