import { describe, expect, it } from "vitest";
import {
  assessmentStateSchema,
  calculateAssessmentMetrics,
  computeAssessmentId,
  createAssessmentState,
  isAssessmentId,
} from "./assessment.js";

describe("Assessment Security Domain", () => {
  const objective = {
    title: "Gateway Router Firmware Assessment",
    target_technologies: ["mips", "embedded_linux", "busybox"],
    compliance_frameworks: ["OWASP_IOT_TOP_10"],
    focus_areas: ["hardcoded_credentials", "remote_services"],
    depth: "standard" as const,
  };

  const scope = {
    allowed_targets: ["/opt/firmware/squashfs-root", "192.168.1.1"],
    denied_targets: ["192.168.1.254"],
    authorized_by: "Security Review Board",
    authorization_reference: "SEC-2026-0891",
    valid_until: "2026-12-31T23:59:59.000Z",
    allow_active_verification: true,
  };

  it("computes deterministic assessment IDs", () => {
    const id1 = computeAssessmentId({
      title: objective.title,
      authorized_by: scope.authorized_by,
      created_at: "2026-11-05T10:00:00.000Z",
    });
    const id2 = computeAssessmentId({
      title: objective.title,
      authorized_by: scope.authorized_by,
      created_at: "2026-11-05T10:00:00.000Z",
    });

    expect(id1).toBe(id2);
    expect(isAssessmentId(id1)).toBe(true);
    expect(id1).toMatch(/^asm_[a-f0-9]{64}$/u);
  });

  it("creates initial AssessmentState with zero metrics", () => {
    const state = createAssessmentState({
      objective,
      scope,
      now: "2026-11-05T10:00:00.000Z",
    });

    expect(state.phase).toBe("initialization");
    expect(state.assets).toHaveLength(0);
    expect(state.findings).toHaveLength(0);
    expect(state.metrics.total_findings).toBe(0);
    expect(state.metrics.critical_findings).toBe(0);

    const parsed = assessmentStateSchema.parse(state);
    expect(parsed.assessment_id).toBe(state.assessment_id);
  });

  it("calculates aggregate metrics correctly across findings", () => {
    const metrics = calculateAssessmentMetrics(
      [
        {
          id: "ast_1111111111111111111111111111111111111111111111111111111111111111",
          name: "router",
          type: "firmware_image",
          path: null,
          digest: null,
          architecture: null,
          version: null,
          environment: null,
          tags: [],
          metadata: {},
        },
      ],
      [
        {
          id: "fnd_1111111111111111111111111111111111111111111111111111111111111111",
          name: "Vuln 1",
          affected_asset: {
            id: "ast_1111111111111111111111111111111111111111111111111111111111111111",
            name: "router",
            type: "firmware_image",
          },
          location: {
            file: null,
            function: null,
            line: null,
            column: null,
            end_line: null,
            module: null,
            component: null,
            address: null,
            offset: null,
          },
          technical_description: "Desc",
          root_cause: "Cause",
          evidence_ids: [],
          reproduction_steps: [],
          impact: { description: "Impact", attack_prerequisites: [], exploitability: "UNKNOWN" },
          severity: { level: "CRITICAL", cvss_vector: null, cvss_score: 9.8, justification: "" },
          confidence: { level: "CONFIRMED", false_positive_considerations: [], verification_method: null },
          remediation: { description: "Fix", code_diff: null, config_example: null, priority: "IMMEDIATE", validation_procedure: "" },
          classification: { cve: [], cwe: [], capec: [], mitre_attack: [], owasp: [] },
          verification_status: "VERIFIED",
          provenance: { discovered_by: "agent", discovered_at: "2026-11-05T12:00:00.000Z", verified_by: null, verified_at: null },
        },
        {
          id: "fnd_2222222222222222222222222222222222222222222222222222222222222222",
          name: "Vuln 2",
          affected_asset: {
            id: "ast_1111111111111111111111111111111111111111111111111111111111111111",
            name: "router",
            type: "firmware_image",
          },
          location: {
            file: null,
            function: null,
            line: null,
            column: null,
            end_line: null,
            module: null,
            component: null,
            address: null,
            offset: null,
          },
          technical_description: "Desc 2",
          root_cause: "Cause 2",
          evidence_ids: [],
          reproduction_steps: [],
          impact: { description: "Impact", attack_prerequisites: [], exploitability: "UNKNOWN" },
          severity: { level: "HIGH", cvss_vector: null, cvss_score: 7.5, justification: "" },
          confidence: { level: "HIGH", false_positive_considerations: [], verification_method: null },
          remediation: { description: "Fix", code_diff: null, config_example: null, priority: "SHORT_TERM", validation_procedure: "" },
          classification: { cve: [], cwe: [], capec: [], mitre_attack: [], owasp: [] },
          verification_status: "UNVERIFIED",
          provenance: { discovered_by: "agent", discovered_at: "2026-11-05T12:00:00.000Z", verified_by: null, verified_at: null },
        },
      ],
    );

    expect(metrics.total_assets).toBe(1);
    expect(metrics.total_findings).toBe(2);
    expect(metrics.critical_findings).toBe(1);
    expect(metrics.high_findings).toBe(1);
    expect(metrics.verified_findings).toBe(1);
  });
});

