import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import type { CliInstance } from "./types.js";
import { registerSecurityCommands } from "./securityCommands.js";

function createTestSecurityCli(dbPath: string) {
  const logger = pino({ enabled: false });
  const commands = new Map<string, any>();
  const cli = {
    command: (name: string, definition: any) => {
      commands.set(name, definition);
      return cli;
    },
  } as unknown as CliInstance;
  registerSecurityCommands(cli, logger, {
    REA_SECURITY_DB_PATH: dbPath,
  });
  return commands;
}

describe("securityCommands — Positive Execution & Persistence (M1.1B)", () => {
  let tempDir: string;
  let dbPath: string;
  let commands: Map<string, any>;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rea-sec-cli-pos-"));
    dbPath = join(tempDir, "blackboard.db");
    commands = createTestSecurityCli(dbPath);
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

  it("generates markdown report from exported assessment JSON file via security-report command", async () => {
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

    await writeFile(
      assessmentFile,
      JSON.stringify(assessmentData, null, 2),
      "utf8",
    );

    const command = commands.get(CLI_COMMANDS.securityReport);
    expect(command).toBeDefined();

    const result = await command.run({
      args: { path: assessmentFile },
      options: { format: "markdown" },
    });

    expect(result.status).toBe("SUCCESS");
    expect(result.format).toBe("markdown");
    expect(result.report).toContain(
      "# Security Assessment Report: Test Objective",
    );
    expect(result.report).toContain("REF-123");
  });

  it("performs security scan via shared SecurityAssessmentService and reconstructs persisted report by assessment_id", async () => {
    const scanCmd = commands.get(CLI_COMMANDS.securityScan);
    const reportCmd = commands.get(CLI_COMMANDS.securityReport);
    expect(scanCmd).toBeDefined();
    expect(reportCmd).toBeDefined();

    const scanResult = await scanCmd.run({
      args: { path: tempDir },
      options: {
        format: "json",
        depth: "surface",
        authorizedBy: "Auto Test",
        reference: "TEST-RUN-001",
      },
    });

    expect(["COMPLETED", "PARTIAL", "NOT_SCANNED"]).toContain(
      scanResult.status,
    );
    expect(scanResult.assessment_id).toMatch(/^asm_[a-f0-9]{64}$/);
    expect(scanResult.metrics).toBeDefined();
    expect(scanResult.scan_execution).toBeDefined();
    expect(scanResult.format).toBe("json");

    for (const fmt of ["markdown", "json", "sarif"] as const) {
      const repResult = await reportCmd.run({
        args: { path: scanResult.assessment_id },
        options: { format: fmt },
      });
      expect(repResult.status).toBe("SUCCESS");
      expect(repResult.assessment_id).toBe(scanResult.assessment_id);
      expect(repResult.assessment_status).toBe(scanResult.status);
      expect(repResult.format).toBe(fmt);
      expect(typeof repResult.report).toBe("string");
      expect(repResult.report.length).toBeGreaterThan(20);
    }
  });
});

describe("securityCommands — Fail-Closed Negative Boundaries (M1.1B)", () => {
  let tempDir: string;
  let dbPath: string;
  let commands: Map<string, any>;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rea-sec-cli-neg-"));
    dbPath = join(tempDir, "blackboard.db");
    commands = createTestSecurityCli(dbPath);
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
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

  it("fails closed on invalid path, path traversal, malformed assessment ID, and unknown assessment ID", async () => {
    const scanCmd = commands.get(CLI_COMMANDS.securityScan);
    const reportCmd = commands.get(CLI_COMMANDS.securityReport);

    const missingScan = await scanCmd.run({
      args: { path: join(tempDir, "does-not-exist.squashfs") },
      options: {
        format: "json",
        depth: "standard",
        authorizedBy: "tester",
        reference: "NEG-1",
      },
    });
    expect(missingScan.status).toBe("FAILED");
    expect(missingScan.error_code).toBe("INVALID_TARGET");
    expect(missingScan.report).toBeUndefined();

    const traversalScan = await scanCmd.run({
      args: { path: "../outside-target.bin" },
      options: {
        format: "json",
        depth: "standard",
        authorizedBy: "tester",
        reference: "NEG-2",
      },
    });
    expect(traversalScan.status).toBe("FAILED");
    expect(traversalScan.error_code).toBe("AUTHORIZATION_DENIED");

    const badIdReport = await reportCmd.run({
      args: { path: "asm_not_valid_hex" },
      options: { format: "markdown" },
    });
    expect(badIdReport.status).toBe("FAILED");
    expect(badIdReport.error_code).toBe("INVALID_TARGET");
    expect(badIdReport.report).toBeUndefined();

    const unknownIdReport = await reportCmd.run({
      args: {
        path: "asm_0000000000000000000000000000000000000000000000000000000000000000",
      },
      options: { format: "markdown" },
    });
    expect(unknownIdReport.status).toBe("FAILED");
    expect(unknownIdReport.error_code).toBe("ASSESSMENT_NOT_FOUND");
    expect(unknownIdReport.report).toBeUndefined();

    const corruptedFile = join(tempDir, "corrupted.json");
    await writeFile(corruptedFile, "{not valid json", "utf8");
    const corruptedReport = await reportCmd.run({
      args: { path: corruptedFile },
      options: { format: "markdown" },
    });
    expect(corruptedReport.status).toBe("FAILED");
    expect(corruptedReport.error_code).toBe("STORAGE_ERROR");

    if (process.platform !== "win32") {
      const unreadableFile = join(tempDir, "unreadable.bin");
      await writeFile(unreadableFile, "secret", "utf8");
      await chmod(unreadableFile, 0o000);
      try {
        const permScan = await scanCmd.run({
          args: { path: unreadableFile },
          options: {
            format: "json",
            depth: "standard",
            authorizedBy: "tester",
            reference: "NEG-6",
          },
        });
        expect(permScan.status).toBe("FAILED");
        expect(permScan.error_code).toBe("AUTHORIZATION_DENIED");
      } finally {
        await chmod(unreadableFile, 0o600);
      }
    }
  });
});
