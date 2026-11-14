import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { SqliteBlackboardStorage } from "./SqliteBlackboardStorage.js";
import { SqlitePackBoardStore } from "../packboard/SqlitePackBoardStore.js";
import type { Lead } from "../../domain/security/packboard/types.js";
import type { AssessmentRecord, AssetRecord, ObservationRecord, TaskRecord, AgentRegistration, FindingRecord } from "../../domain/security/blackboard/types.js";

function setupTempDir(): string {
  return mkdtempSync(join(tmpdir(), "rea-phase2-smoke-"));
}

function makeMockAssessment(id: string, name: string): AssessmentRecord {
  return {
    id: id as any,
    name,
    status: "active",
    objective: {
      title: "Security Assessment",
      target_technologies: ["Linux"],
      compliance_frameworks: [],
      focus_areas: [],
      depth: "standard",
    },
    authorization: {
      allowed_targets: ["target.bin"],
      denied_targets: [],
      authorized_by: "secops",
      authorization_reference: "AUTH-1",
      valid_until: new Date(Date.now() + 100000).toISOString(),
      allow_active_verification: false,
    },
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
    created_at: Date.now(),
    updated_at: Date.now(),
  };
}

describe("Phase 2 Smoke Check 1: Single Database & Shared Connection", () => {
  let tempDir: string;
  let dbPath: string;
  let activeStorage: SqliteBlackboardStorage | undefined;

  beforeEach(() => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
    activeStorage = undefined;
  });

  afterEach(() => {
    if (activeStorage) {
      try {
        activeStorage.close();
      } catch {
        // ignore
      }
    }
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("SqlitePackBoardStore and all repositories use the exact same blackboard.db", async () => {
    const storage = new SqliteBlackboardStorage({ dbPath });
    activeStorage = storage;
    const assessmentRes = await storage.assessments.create(
      makeMockAssessment("asm_smoke_1", "Smoke Assessment"),
    );
    expect(assessmentRes.ok).toBe(true);

    const packBoard = new SqlitePackBoardStore({ storage });
    const lead: Lead = {
      id: "lead-smoke-1" as any,
      assessment_id: "asm_smoke_1" as any,
      fingerprint: "fp-smoke-1",
      title: "Shared DB Lead",
      description: "Testing single DB architecture",
      asset_id: "asset-1" as any,
      location: {
        file: "main.c",
        function: "main",
        line: 42,
        column: 1,
        end_line: 42,
        module: null,
        component: null,
        address: null,
        offset: null,
      },
      classification: {
        cve: [],
        cwe: ["CWE-120" as any],
        capec: [],
        mitre_attack: [],
        owasp: [],
      },
      severity: "HIGH",
      confidence: "CONFIRMED",
      status: "open",
      smoke_score: 5,
      cas_version: 1,
      provenance: "source_scan",
      claim: null,
      votes: [],
      evidence_hashes: ["sha256:abc"],
      created_at: Date.now(),
      updated_at: Date.now(),
    };

    const postRes = await packBoard.postLead(lead);
    expect(postRes.ok).toBe(true);

    // Verify task is visible through TaskRepository on the exact same database
    const taskRes = await storage.tasks.getById("asm_smoke_1" as any, "lead-smoke-1");
    expect(taskRes.ok).toBe(true);
    expect(taskRes.ok && taskRes.value).not.toBeNull();
    if (taskRes.ok && taskRes.value) {
      expect(taskRes.value.title).toBe("Shared DB Lead");
      expect(taskRes.value.smoke_score).toBe(5);
      expect(taskRes.value.task_type).toBe("lead_investigation");
    }

    // Verify closing packboard does not close the shared storage connection
    packBoard.close();
    const probeRes = await storage.assessments.findById("asm_smoke_1" as any);
    expect(probeRes.ok).toBe(true);

    storage.close();
  });
});

describe("Phase 2 Smoke Check 2: Migration and Restart Recovery", () => {
  let tempDir: string;
  let dbPath: string;
  let activeStorage: SqliteBlackboardStorage | undefined;

  beforeEach(() => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
    activeStorage = undefined;
  });

  afterEach(() => {
    if (activeStorage) {
      try {
        activeStorage.close();
      } catch {
        // ignore
      }
    }
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("migrates existing Phase 1 leads into tasks and survives application restart", async () => {
    // 1. Seed a legacy database with Phase 1 schema
    const rawDb = new DatabaseSync(dbPath);
    rawDb.exec(`
      CREATE TABLE leads (
        id TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        location_json TEXT NOT NULL,
        classification_json TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        status TEXT NOT NULL,
        smoke_score INTEGER NOT NULL DEFAULT 1,
        cas_version INTEGER NOT NULL DEFAULT 1,
        provenance TEXT NOT NULL,
        claim_json TEXT,
        votes_json TEXT NOT NULL DEFAULT '[]',
        evidence_hashes_json TEXT NOT NULL DEFAULT '[]',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
    `);

    rawDb.prepare(`
      INSERT INTO leads VALUES (
        'legacy-lead-1', 'assess-migrate-1', 'fp-leg-1', 'Legacy Buffer Overflow', 'Old lead desc',
        'asset-root', '{"file":"lib.c"}', '{"cwe":["CWE-120"]}', 'HIGH', 'CONFIRMED',
        'OPEN', 3, 1, 'firmware_scan', NULL, '[]', '["hash123"]', 1000, 1000
      )
    `).run();
    rawDb.close();

    // 2. Open with SqliteBlackboardStorage (runs migrations)
    let storage = new SqliteBlackboardStorage({ dbPath });
    activeStorage = storage;
    const migratedTask = await storage.tasks.getById("assess-migrate-1" as any, "legacy-lead-1");
    expect(migratedTask.ok).toBe(true);
    expect(migratedTask.ok && migratedTask.value?.title).toBe("Legacy Buffer Overflow");
    expect(migratedTask.ok && migratedTask.value?.smoke_score).toBe(3);

    // 3. Restart application / reconnect to verify persistence
    storage.close();
    storage = new SqliteBlackboardStorage({ dbPath });
    activeStorage = storage;

    const reopenedTask = await storage.tasks.getById("assess-migrate-1" as any, "legacy-lead-1");
    expect(reopenedTask.ok).toBe(true);
    expect(reopenedTask.ok && reopenedTask.value?.title).toBe("Legacy Buffer Overflow");
    expect(reopenedTask.ok && reopenedTask.value?.fencing_token).toBe(1);

    storage.close();
    activeStorage = undefined;
  });
});

describe("Phase 2 Smoke Check 3: Stale Fencing Token Rejection Across Mutations", () => {
  let tempDir: string;
  let dbPath: string;

  beforeEach(() => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
  });

  afterEach(() => {
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("rejects stale fencing tokens for complete, fail, and result updates", async () => {
    const storage = new SqliteBlackboardStorage({ dbPath });
    const assessmentId = "asm_fencing_smoke" as any;

    await storage.assessments.create(
      makeMockAssessment(assessmentId, "Fencing Smoke"),
    );

    const task: TaskRecord = {
      id: "task-fence-1",
      assessment_id: assessmentId,
      task_type: "decompilation",
      title: "Decompile binary",
      description: "Analyze binary symbols",
      asset_id: "asset-1" as any,
      priority: "normal",
      status: "open",
      blocked_by: [],
      fencing_token: 1,
      cas_version: 1,
      claim: null,
      result: null,
      metadata: {},
      created_at: Date.now(),
      updated_at: Date.now(),
    };
    await storage.tasks.create(task);

    // Worker 1 claims task -> token advances to 2
    const claimRes = await storage.tasks.claimTask(assessmentId, "task-fence-1", {
      agent_id: "worker-1",
      host_id: "host-1",
      pid: 1234,
      process_start_time: 1000,
      rea_run_id: "run-1",
      claimed_at: Date.now(),
      lease_until: Date.now() + 60000,
    }, 1);
    expect(claimRes.ok).toBe(true);
    expect(claimRes.ok && claimRes.value.fencing_token).toBe(2);

    // Stale Worker with token 1 tries completeTask -> Rejected
    const completeStale = await storage.tasks.completeTask(assessmentId, "task-fence-1", 1, { data: "stale" });
    expect(completeStale.ok).toBe(false);
    if (!completeStale.ok) {
      expect(completeStale.error.code).toBe("STALE_FENCING_TOKEN");
    }

    // Stale Worker with token 1 tries failTask -> Rejected
    const failStale = await storage.tasks.failTask(assessmentId, "task-fence-1", 1, "timeout");
    expect(failStale.ok).toBe(false);
    if (!failStale.ok) {
      expect(failStale.error.code).toBe("STALE_FENCING_TOKEN");
    }

    // Stale Worker with token 1 tries updateResult -> Rejected
    const updateStale = await storage.tasks.updateResult(assessmentId, "task-fence-1", 1, { partial: true });
    expect(updateStale.ok).toBe(false);
    if (!updateStale.ok) {
      expect(updateStale.error.code).toBe("STALE_FENCING_TOKEN");
    }

    // Active Worker with valid token 2 updates result and completes
    const updateValid = await storage.tasks.updateResult(assessmentId, "task-fence-1", 2, { partial: true });
    expect(updateValid.ok).toBe(true);

    const completeValid = await storage.tasks.completeTask(assessmentId, "task-fence-1", 2, { output: "done" });
    expect(completeValid.ok).toBe(true);

    storage.close();
  });
});

describe("Phase 2 Smoke Check 4: Transactional Outbox Across Repositories & Rollback", () => {
  let tempDir: string;
  let dbPath: string;

  beforeEach(() => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
  });

  afterEach(() => {
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("inserts audit events in the same transaction and rolls back atomically on failure", async () => {
    const storage = new SqliteBlackboardStorage({ dbPath });
    const assessmentId = "asm_outbox_smoke" as any;

    // 1. Mutate through repositories
    await storage.assessments.create(
      makeMockAssessment(assessmentId, "Outbox Smoke"),
    );

    await storage.assets.create({
      id: "asset-outbox-1" as any,
      assessment_id: assessmentId,
      parent_asset_id: null,
      name: "target.bin",
      type: "compiled_binary",
      path: "/bin/target.bin",
      digest: null,
      architecture: null,
      version: null,
      environment: null,
      tags: [],
      metadata: {},
      created_at: Date.now(),
    });

    await storage.observations.record({
      assessment_id: assessmentId,
      asset_id: "asset-outbox-1" as any,
      key: "architecture",
      value: "arm64",
      confidence: 0.9,
      source_tool: "readelf",
      agent_id: "test-agent",
      evidence_id: null,
      created_at: Date.now(),
    });

    // Check outbox entries exist
    const db = storage.getDatabase();
    const rows = db.prepare("SELECT event_type FROM transactional_outbox").all() as Array<{ event_type: string }>;
    const eventTypes = rows.map((r) => r.event_type);
    expect(eventTypes).toContain("ASSESSMENT_CREATED");
    expect(eventTypes).toContain("ASSET_CREATED");
    expect(eventTypes).toContain("OBSERVATION_RECORDED");

    // 2. Test rollback atomicity
    const countBefore = db.prepare("SELECT COUNT(*) as c FROM transactional_outbox").get() as { c: number };
    expect(() => {
      storage.transaction((tx) => {
        tx.queueOutbox("FAILED_EVENT", "test", "id1", assessmentId, {});
        tx.db.prepare("INSERT INTO assets (id, assessment_id, name, type, created_at) VALUES (?, ?, ?, ?, ?)").run(
          "should-rollback", assessmentId, "fake", "binary", Date.now()
        );
        throw new Error("Simulated failure inside transaction");
      });
    }).toThrow("Simulated failure inside transaction");

    const countAfter = db.prepare("SELECT COUNT(*) as c FROM transactional_outbox").get() as { c: number };
    expect(countAfter.c).toBe(countBefore.c);

    const assetCheck = db.prepare("SELECT * FROM assets WHERE id = 'should-rollback'").get();
    expect(assetCheck).toBeUndefined();

    storage.close();
  });
});
