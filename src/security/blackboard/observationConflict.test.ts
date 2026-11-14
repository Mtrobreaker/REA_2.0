import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SqliteBlackboardStorage } from "./SqliteBlackboardStorage.js";
import type { AssessmentId } from "../../domain/security/assessment.js";
import type { AssetId } from "../../domain/security/asset.js";
import type { AssessmentRecord, BlackboardAssetRecord } from "../../domain/security/blackboard/types.js";

describe("Observation Conflict Preservation (T21)", () => {
  let tempDir: string;
  let storage: SqliteBlackboardStorage;

  const assessmentId = "asm_conflict_000000000000000000000000000000000000000000000000000000" as AssessmentId;
  const assetId = "ast_target_binary_0000000000000000000000000000000000000000000000000" as AssetId;

  beforeEach(async () => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-obs-conflict-"));
    const dbPath = join(tempDir, "blackboard.db");
    const journalPath = join(tempDir, "packboard-audit.jsonl");
    storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId });

    // Seed assessment & asset
    const asm: AssessmentRecord = {
      id: assessmentId,
      name: "Conflict Test Assessment",
      status: "active",
      objective: { title: "Test", target_technologies: [], compliance_frameworks: [], focus_areas: [], depth: "standard" },
      authorization: { allowed_targets: ["target.bin"], denied_targets: [], authorized_by: "Test", authorization_reference: "REF", valid_until: new Date().toISOString(), allow_active_verification: false },
      metrics: { total_assets: 1, total_findings: 0, critical_findings: 0, high_findings: 0, medium_findings: 0, low_findings: 0, info_findings: 0, verified_findings: 0 },
      created_at: Date.now(),
      updated_at: Date.now(),
    };
    await storage.assessments.create(asm);

    const asset: BlackboardAssetRecord = {
      id: assetId,
      assessment_id: assessmentId,
      parent_asset_id: null,
      name: "target.bin",
      type: "compiled_binary",
      path: "/usr/bin/target",
      digest: { sha256: "c".repeat(64) },
      architecture: null,
      version: null,
      environment: null,
      tags: [],
      metadata: {},
      created_at: Date.now(),
    };
    await storage.assets.create(asset);
  });

  afterEach(() => {
    storage.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("T21: preserves conflicting observations with full provenance rather than overwriting", async () => {
    // 1. Agent A reports architecture ARM with confidence 0.85
    const obsARes = await storage.observations.record({
      assessment_id: assessmentId,
      asset_id: assetId,
      key: "architecture",
      value: "ARM",
      confidence: 0.85,
      source_tool: "heuristic_string_scan",
      agent_id: "agent_scanner_01",
      evidence_id: "ev_string_arm_001",
      created_at: 1000,
    });
    expect(obsARes.ok).toBe(true);
    if (!obsARes.ok) return;
    expect(obsARes.value.is_conflict).toBe(false);

    // 2. Agent B reports architecture MIPS with confidence 0.95 (conflicting fact!)
    const obsBRes = await storage.observations.record({
      assessment_id: assessmentId,
      asset_id: assetId,
      key: "architecture",
      value: "MIPS",
      confidence: 0.95,
      source_tool: "elf_header_parser",
      agent_id: "agent_disassembler_02",
      evidence_id: "ev_elf_hdr_mips_002",
      created_at: 2000,
    });
    expect(obsBRes.ok).toBe(true);
    if (!obsBRes.ok) return;
    // Conflict is immediately detected and flagged
    expect(obsBRes.value.is_conflict).toBe(true);

    // 3. Query all observations for this asset & key: BOTH MUST EXIST!
    const allObsRes = await storage.observations.listByAsset(assessmentId, assetId, "architecture");
    expect(allObsRes.ok).toBe(true);
    if (!allObsRes.ok) return;

    expect(allObsRes.value.length).toBe(2);

    const values = allObsRes.value.map((o) => o.value);
    expect(values).toContain("ARM");
    expect(values).toContain("MIPS");

    // Both observations are marked as in conflict
    for (const obs of allObsRes.value) {
      expect(obs.is_conflict).toBe(true);
      expect(obs.evidence_id).not.toBeNull();
    }

    // 4. getConflicts groups them into a structured conflict report
    const conflictsRes = await storage.observations.getConflicts(assessmentId, assetId);
    expect(conflictsRes.ok).toBe(true);
    if (!conflictsRes.ok) return;

    expect(conflictsRes.value.length).toBe(1);
    const group = conflictsRes.value[0];
    expect(group?.key).toBe("architecture");
    expect(group?.observations.length).toBe(2);
    expect(group?.observations[0]?.agent_id).toBe("agent_scanner_01");
    expect(group?.observations[1]?.agent_id).toBe("agent_disassembler_02");

    // 5. Verify transactional outbox logged OBSERVATION_CONFLICT_DETECTED
    const db = storage.getDatabase();
    const conflictEvents = db
      .prepare("SELECT * FROM transactional_outbox WHERE event_type = 'OBSERVATION_CONFLICT_DETECTED'")
      .all() as any[];

    expect(conflictEvents.length).toBe(1);
    const payload = JSON.parse(conflictEvents[0].payload_json);
    expect(payload.key).toBe("architecture");
    expect(payload.new_value).toBe("MIPS");
    expect(payload.previous_values.length).toBe(1);
    expect(payload.previous_values[0].value).toBe("ARM");
  });
});

