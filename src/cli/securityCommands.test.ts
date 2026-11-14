import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import type { CliInstance } from "./types.js";
import { registerSecurityCommands } from "./securityCommands.js";

describe("securityCommands", () => {
  let tempDir: string;
  let commands: Map<string, any>;
  const logger = pino({ enabled: false });

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rea-sec-cli-test-"));
    commands = new Map<string, any>();
    const cli = {
      command: (name: string, definition: any) => {
        commands.set(name, definition);
        return cli;
      },
    } as unknown as CliInstance;
    registerSecurityCommands(cli, logger, {});
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("calculates CVSS v3.1 score and severity via security-cvss command", async () => {
    const command = commands.get(CLI_COMMANDS.securityCvss);
    expect(command).toBeDefined();

    const output = await command.run({
      args: {
        vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      },
    });

    expect(output.status).toBe("SUCCESS");
    expect(output.score).toBe(9.8);
    expect(output.severity).toBe("CRITICAL");
    expect(output.exploitability_subscore).toBe(3.9);
    expect(output.impact_subscore).toBe(5.9);
  });

  it("handles malformed CVSS vector gracefully", async () => {
    const command = commands.get(CLI_COMMANDS.securityCvss);
    const output = await command.run({
      args: {
        vector: "INVALID:VECTOR",
      },
    });

    expect(output.status).toBe("ERROR");
    expect(output.error).toBeDefined();
  });

  it("generates markdown report from assessment JSON file via security-report command", async () => {
    const assessmentFile = join(tempDir, "sample-assessment.json");
    const assessmentData = {
      assessment_id:
        "asm_1111111111111111111111111111111111111111111111111111111111111111",
      objective: {
        title: "Test Objective",
        target_technologies: [],
        compliance_frameworks: [],
        focus_areas: [],
        depth: "standard",
      },
      scope: {
        allowed_targets: [tempDir],
        denied_targets: [],
        authorized_by: "Test Lead",
        authorization_reference: "REF-123",
        valid_until: "2026-12-31T23:59:59Z",
        allow_active_verification: false,
      },
      phase: "completed",
      created_at: "2026-11-05T12:00:00Z",
      updated_at: "2026-11-05T12:00:00Z",
      completed_at: "2026-11-05T12:00:00Z",
      assets: [],
      findings: [],
      metrics: {
        total_assets: 0,
        total_findings: 0,
        critical_findings: 0,
        high_findings: 0,
        medium_findings: 0,
        low_findings: 0,
        info_findings: 0,
        verified_findings: 0,
      },
    };

    await writeFile(assessmentFile, JSON.stringify(assessmentData, null, 2), "utf8");

    const command = commands.get(CLI_COMMANDS.securityReport);
    expect(command).toBeDefined();

    const result = await command.run({
      args: { path: assessmentFile },
      options: { format: "markdown" },
    });

    expect(result.status).toBe("SUCCESS");
    expect(result.format).toBe("markdown");
    expect(result.report).toContain("# Security Assessment Report: Test Objective");
    expect(result.report).toContain("REF-123");
  });

  it("performs security scan against authorized directory via security-scan command", async () => {
    const command = commands.get(CLI_COMMANDS.securityScan);
    expect(command).toBeDefined();

    const result = await command.run({
      args: { path: tempDir },
      options: {
        format: "json",
        depth: "surface",
        authorizedBy: "Auto Test",
        reference: "TEST-RUN-001",
      },
    });

    expect(result.status).toBe("COMPLETED");
    expect(result.assessment_id).toMatch(/^asm_[a-f0-9]{64}$/);
    expect(result.metrics).toBeDefined();
    expect(result.format).toBe("json");
  });
});
