import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SqliteBlackboardStorage } from "./SqliteBlackboardStorage.js";
import type { AssessmentId } from "../../domain/security/assessment.js";

describe("SqliteBlackboardStorage: Unified DB & TransactionContext", () => {
  let tempDir: string;
  let dbPath: string;
  let journalPath: string;
  let storage: SqliteBlackboardStorage;
  const assessmentId = "asm_tx_test_00000000000000000000000000000000000000000000000000000000" as AssessmentId;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-blackboard-tx-"));
    dbPath = join(tempDir, "blackboard.db");
    journalPath = join(tempDir, "packboard-audit.jsonl");
    storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId });
  });

  afterEach(() => {
    storage.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("creates unified blackboard.db with WAL mode and schema tables", () => {
    expect(existsSync(dbPath)).toBe(true);
    const db = storage.getDatabase();

    const pragmaRes = db.prepare("PRAGMA journal_mode;").get() as any;
    expect(pragmaRes.journal_mode.toLowerCase()).toBe("wal");

    // Verify all 7 tables exist
    const tables = [
      "assessments",
      "assets",
      "observations",
      "tasks",
      "agents",
      "findings",
      "transactional_outbox",
      "schema_migrations",
    ];

    for (const t of tables) {
      const row = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(t);
      expect(row).toBeDefined();
    }
  });

  it("atomically commits entity changes and transactional outbox events", () => {
    storage.transaction((tx) => {
      tx.db.prepare(`
        INSERT INTO assessments (
          id, name, status, objective_json, authorization_json, metrics_json, created_at, updated_at
        ) VALUES (?, ?, ?, '{}', '{}', '{}', ?, ?)
      `).run(assessmentId, "Test Assessment", "active", Date.now(), Date.now());

      tx.queueOutbox("TEST_EVENT", "assessment", assessmentId, assessmentId, { ok: true });
    });

    const db = storage.getDatabase();
    const asmRow = db.prepare("SELECT * FROM assessments WHERE id = ?").get(assessmentId) as any;
    expect(asmRow).toBeDefined();
    expect(asmRow.name).toBe("Test Assessment");

    const outboxRow = db.prepare("SELECT * FROM transactional_outbox WHERE entity_id = ?").get(assessmentId) as any;
    expect(outboxRow).toBeDefined();
    // Because outbox flusher runs post-commit, flushed is updated to 1
    expect(outboxRow.flushed).toBe(1);
    expect(outboxRow.event_type).toBe("TEST_EVENT");
  });

  it("rolls back all state changes and outbox records when transaction throws an error", () => {
    expect(() => {
      storage.transaction((tx) => {
        tx.db.prepare(`
          INSERT INTO assessments (
            id, name, status, objective_json, authorization_json, metrics_json, created_at, updated_at
          ) VALUES (?, ?, ?, '{}', '{}', '{}', ?, ?)
        `).run(assessmentId, "Should Roll Back", "active", Date.now(), Date.now());

        tx.queueOutbox("FAILING_EVENT", "assessment", assessmentId, assessmentId, { ok: false });

        throw new Error("Simulated transactional failure");
      });
    }).toThrow("Simulated transactional failure");

    const db = storage.getDatabase();
    const asmRow = db.prepare("SELECT * FROM assessments WHERE id = ?").get(assessmentId);
    expect(asmRow).toBeUndefined();

    const outboxRows = db.prepare("SELECT * FROM transactional_outbox WHERE entity_id = ?").all(assessmentId);
    expect(outboxRows.length).toBe(0);
  });

  it("supports re-entrant/nested transactions seamlessly", () => {
    storage.transaction((outerTx) => {
      outerTx.db.prepare(`
        INSERT INTO assessments (
          id, name, status, objective_json, authorization_json, metrics_json, created_at, updated_at
        ) VALUES (?, ?, ?, '{}', '{}', '{}', ?, ?)
      `).run(assessmentId, "Outer", "active", Date.now(), Date.now());

      // Nested transaction call
      storage.transaction((innerTx) => {
        innerTx.db.prepare("UPDATE assessments SET name = 'Inner' WHERE id = ?").run(assessmentId);
      });
    });

    const db = storage.getDatabase();
    const row = db.prepare("SELECT * FROM assessments WHERE id = ?").get(assessmentId) as any;
    expect(row.name).toBe("Inner");
  });
});

