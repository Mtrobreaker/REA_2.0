import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChiefSecurityOrchestrator } from "./orchestrator.js";
import { SqlitePackBoardStore } from "../packboard/SqlitePackBoardStore.js";
import { createAssessmentState } from "../../domain/security/assessment.js";

describe("ChiefSecurityOrchestrator & PackBoard Integration", () => {
  let tempDir: string;
  let packboard: SqlitePackBoardStore;
  let orchestrator: ChiefSecurityOrchestrator;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rea-packboard-orch-test-"));
    const dbPath = join(tempDir, "packboard.db");
    const journalPath = join(tempDir, "packboard-audit.jsonl");
    packboard = new SqlitePackBoardStore({ dbPath, journalPath });
    orchestrator = new ChiefSecurityOrchestrator(undefined, packboard);
  });

  afterEach(async () => {
    packboard.close();
    try {
      await rm(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup
    }
  });

  it("orchestrates assessment with persistent PackBoard and multi-stage adjudication", async () => {
    // 1. Create a test binary with dangerous symbols in authorized temp dir
    const binFile = join(tempDir, "auth_service.elf");
    const fakeElf = Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46]), // ELF magic
      Buffer.from("\0gets\0strcpy\0system\0", "latin1"),
    ]);
    await writeFile(binFile, fakeElf);

    // 2. Set up initial assessment state via domain factory
    const initialState = createAssessmentState({
      objective: {
        title: "PackBoard Integrated Binary & Device Audit",
        target_technologies: ["C", "Binary"],
        compliance_frameworks: ["OWASP Top 10"],
        focus_areas: ["Native Mitigations"],
        depth: "standard",
      },
      scope: {
        allowed_targets: [tempDir],
        denied_targets: [],
        authorized_by: "Security Lead",
        authorization_reference: "AUTH-PACKBOARD-001",
        valid_until: "2026-12-31T23:59:59Z",
        allow_active_verification: false,
      },
    });

    // 3. Run assessment through ChiefSecurityOrchestrator
    const result = await orchestrator.runAssessment(initialState);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const { assessment, agent_logs } = result.value;

    expect(assessment.phase).toBe("completed");
    expect(assessment.completed_at).not.toBeNull();

    // Check that agents logged activities
    expect(agent_logs.reconnaissance.length).toBeGreaterThan(0);
    expect(agent_logs.verification.length).toBeGreaterThan(0);

    // Check that findings were discovered and verified through Adjudication
    expect(assessment.findings.length).toBeGreaterThanOrEqual(1);
    for (const finding of assessment.findings) {
      expect(["VERIFIED", "FALSE_POSITIVE", "UNVERIFIED"]).toContain(
        finding.verification_status,
      );
    }
  });
});
