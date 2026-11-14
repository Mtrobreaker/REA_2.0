import { describe, expect, it } from "vitest";
import type { AuthorizationScope } from "../../domain/security/assessment.js";
import type { SecurityFinding } from "../../domain/security/finding.js";
import type { ProviderProcessSnapshot } from "../../process/ProviderProcess.js";
import { SandboxHarness } from "./sandboxHarness.js";

const sampleScope: AuthorizationScope = {
  allowed_targets: ["/app/source"],
  denied_targets: ["/app/source/secret"],
  authorized_by: "Security Lead",
  authorization_reference: "REF-001",
  valid_until: "2026-12-31T23:59:59Z",
  allow_active_verification: true,
};

const sampleFinding: SecurityFinding = {
  id: "fnd_1111111111111111111111111111111111111111111111111111111111111111",
  name: "SQL Injection in User Search",
  affected_asset: {
    id: "ast_1111111111111111111111111111111111111111111111111111111111111111",
    name: "user-api",
    type: "source_repository",
  },
  location: {
    file: "/app/source/db.ts",
    function: "searchUsers",
    line: 42,
    column: 5,
    end_line: 45,
    module: "db",
    component: null,
    address: null,
    offset: null,
  },
  technical_description: "Unsanitized user input concatenated into query string.",
  root_cause: "Direct string concatenation instead of parameterized prepared statements.",
  evidence_ids: [],
  reproduction_steps: ["Run unit test with ' OR 1=1 -- payload"],
  impact: {
    description: "Full database read access",
    attack_prerequisites: [],
    exploitability: "PROVEN",
  },
  severity: {
    level: "HIGH",
    cvss_vector: null,
    cvss_score: 8.5,
    justification: "High data exposure",
  },
  confidence: {
    level: "CONFIRMED",
    false_positive_considerations: [],
    verification_method: null,
  },
  remediation: {
    description: "Use parameterized query.",
    code_diff: null,
    config_example: null,
    priority: "IMMEDIATE",
    validation_procedure: "Run test suite",
  },
  classification: {
    cve: [],
    cwe: [],
    capec: [],
    mitre_attack: [],
    owasp: [],
  },
  verification_status: "UNVERIFIED",
  provenance: {
    discovered_by: "semgrep",
    discovered_at: "2026-11-05T12:00:00Z",
    verified_by: null,
    verified_at: null,
  },
};

describe("SandboxHarness (Dynamic Verification)", () => {
  it("verifies finding reproduction when output matches expected vulnerability indicator", async () => {
    const mockRunner = async (): Promise<ProviderProcessSnapshot> => ({
      stdout: {
        text: "VULNERABILITY_CONFIRMED: SyntaxError in SQL parser",
        bytes: 50,
        observedBytes: 50,
      },
      stderr: {
        text: "",
        bytes: 0,
        observedBytes: 0,
      },
      exitCode: 0,
      signal: null,
    });

    const harness = new SandboxHarness({
      timeoutMs: 5000,
      maxOutputBytes: 1024 * 1024,
      allowNetwork: false,
      commandRunner: mockRunner,
    });

    const result = await harness.verifyFinding({
      finding: sampleFinding,
      scope: sampleScope,
      testCommand: "node",
      testArgs: ["test-probe.js"],
      expectedPattern: "VULNERABILITY_CONFIRMED",
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.value.status).toBe("VERIFIED");
    expect(result.value.stdout).toContain("VULNERABILITY_CONFIRMED");
    expect(result.value.justification).toContain("Output matched expected vulnerability pattern");
  });

  it("classifies finding as FALSE_POSITIVE when expected vulnerability indicator is absent", async () => {
    const mockRunner = async (): Promise<ProviderProcessSnapshot> => ({
      stdout: {
        text: "All queries properly escaped. No syntax error.",
        bytes: 46,
        observedBytes: 46,
      },
      stderr: {
        text: "",
        bytes: 0,
        observedBytes: 0,
      },
      exitCode: 0,
      signal: null,
    });

    const harness = new SandboxHarness({
      timeoutMs: 5000,
      maxOutputBytes: 1024 * 1024,
      allowNetwork: false,
      commandRunner: mockRunner,
    });

    const result = await harness.verifyFinding({
      finding: sampleFinding,
      scope: sampleScope,
      testCommand: "node",
      testArgs: ["test-probe.js"],
      expectedPattern: "VULNERABILITY_CONFIRMED",
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.value.status).toBe("FALSE_POSITIVE");
    expect(result.value.justification).toContain("did not contain expected vulnerability indicator");
  });

  it("fails closed when target path violates authorization scope", async () => {
    const unauthorizedFinding: SecurityFinding = {
      ...sampleFinding,
      location: {
        ...sampleFinding.location,
        file: "/etc/shadow", // outside allowed targets!
      },
    };

    const harness = new SandboxHarness();
    const result = await harness.verifyFinding({
      finding: unauthorizedFinding,
      scope: sampleScope,
      testCommand: "node",
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("AUTHORIZATION_DENIED");
      expect(result.error.message).toContain("violates authorization scope");
    }
  });

  it("handles execution timeout gracefully", async () => {
    const timeoutRunner = async (): Promise<never> => {
      throw new Error("Command deadline elapsed.");
    };

    const harness = new SandboxHarness({
      timeoutMs: 100,
      maxOutputBytes: 1024,
      allowNetwork: false,
      commandRunner: timeoutRunner,
    });

    const result = await harness.verifyFinding({
      finding: sampleFinding,
      scope: sampleScope,
      testCommand: "node",
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("EXECUTION_TIMEOUT");
    }
  });
});
