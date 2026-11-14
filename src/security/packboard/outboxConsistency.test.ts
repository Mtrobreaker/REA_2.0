import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { SqlitePackBoardStore } from "./SqlitePackBoardStore.js";
import { verifyAuditJournal, type AuditRecord } from "./HmacAuditJournal.js";
import type { Lead } from "../../domain/security/packboard/types.js";
import type { AssessmentId } from "../../domain/security/assessment.js";
import type { AssetId } from "../../domain/security/asset.js";

const assessment1 = "asm_outbox_consistency_test_12345" as AssessmentId;
const asset1 = "ast_outbox_asset_test_12345" as AssetId;

const createDummyLead = (id: string, fingerprint: string): Lead => ({
  id: `lead_${id.padEnd(64, "0")}` as any,
  assessment_id: assessment1,
  fingerprint,
  title: `Lead Title ${id}`,
  description: `Lead Description ${id}`,
  asset_id: asset1,
  location: {
    file: "src/auth.c",
    function: "login",
    line: 10,
    column: 1,
    end_line: 10,
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
  confidence: "MEDIUM",
  status: "open",
  smoke_score: 1,
  cas_version: 1,
  provenance: "source_scan",
  claim: null,
  votes: [],
  evidence_hashes: ["sha256_evidence_alpha"],
  created_at: 1000,
  updated_at: 1000,
});

describe("OutboxConsistency: Atomic Commit & Idempotency (T03, T23)", () => {
  let tempDir: string;
  let dbPath: string;
  let journalPath: string;
  let store: SqlitePackBoardStore;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-outbox-test-"));
    dbPath = join(tempDir, "packboard.db");
    journalPath = join(tempDir, "packboard-audit.jsonl");
    store = new SqlitePackBoardStore({ dbPath, journalPath, assessmentId: assessment1 });
  });

  afterEach(() => {
    store.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup
    }
  });

  it("T03: atomically commits lead and flushes outbox to audit journal", async () => {
    const lead = createDummyLead("alpha", "1".repeat(64));
    const res = await store.postLead(lead);
    expect(res.ok).toBe(true);

    const journalContent = readFileSync(journalPath, "utf8").trim();
    expect(journalContent.length).toBeGreaterThan(0);
    const lines = journalContent.split("\n");
    expect(lines.length).toBe(1);

    const record = JSON.parse(lines[0]!) as AuditRecord;
    expect(record.action).toBe("POST_LEAD");
    expect(record.lead_id).toBe(lead.id);
    expect(record.event_id).toBeDefined();

    // Verify outbox table in SQLite has flushed = 1
    const rawDb = new DatabaseSync(dbPath);
    const outboxRow = rawDb.prepare("SELECT * FROM transactional_outbox WHERE entity_id = ?").get(lead.id) as any;
    rawDb.close();

    expect(outboxRow).toBeDefined();
    expect(outboxRow.flushed).toBe(1);
    expect(outboxRow.event_id).toBe(record.event_id);
  });

  it("T23: idempotently reconciles outbox post-fsync crash without duplicating journal entries", async () => {
    // Step 1: Post initial lead
    const lead1 = createDummyLead("lead1", "1".repeat(64));
    await store.postLead(lead1);

    const initialJournalLines = readFileSync(journalPath, "utf8").trim().split("\n");
    expect(initialJournalLines.length).toBe(1);
    const initialRecord = JSON.parse(initialJournalLines[0]!) as AuditRecord;
    const committedEventId = initialRecord.event_id!;

    // Step 2: Simulate crash window: Reset SQLite outbox record to flushed = 0
    // (simulating that the process crashed right after fsyncing the JSONL line, before SQLite updated flushed = 1)
    store.close();

    const rawDb = new DatabaseSync(dbPath);
    rawDb.prepare("UPDATE transactional_outbox SET flushed = 0 WHERE event_id = ?").run(committedEventId);
    rawDb.close();

    // Step 3: Reopen store. Startup reconciliation runs!
    const reopenedStore = new SqlitePackBoardStore({
      dbPath,
      journalPath,
      assessmentId: assessment1,
    });

    // Check that journal lines count DID NOT increase (no duplicate record was appended!)
    const reconciledJournalLines = readFileSync(journalPath, "utf8").trim().split("\n");
    expect(reconciledJournalLines.length).toBe(1);

    // Verify that SQLite outbox record is now marked flushed = 1
    const verifyDb = new DatabaseSync(dbPath);
    const updatedRow = verifyDb.prepare("SELECT * FROM transactional_outbox WHERE event_id = ?").get(committedEventId) as any;
    verifyDb.close();

    expect(updatedRow.flushed).toBe(1);

    // Verify cryptographic integrity of journal
    const verifyRes = verifyAuditJournal(journalPath, reopenedStore.getKeyringManager().getKeyResolver());
    expect(verifyRes.ok).toBe(true);

    reopenedStore.close();
  });
});

describe("OutboxConsistency: Crash Recovery & Tamper Rejection (T04)", () => {
  let tempDir: string;
  let dbPath: string;
  let journalPath: string;
  let store: SqlitePackBoardStore;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-outbox-crash-test-"));
    dbPath = join(tempDir, "packboard.db");
    journalPath = join(tempDir, "packboard-audit.jsonl");
    store = new SqlitePackBoardStore({ dbPath, journalPath, assessmentId: assessment1 });
  });

  afterEach(() => {
    store.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup
    }
  });

  it("recovers from mid-write crash by truncating incomplete trailing line and re-flushing cleanly", async () => {
    const lead1 = createDummyLead("clean1", "2".repeat(64));
    await store.postLead(lead1);
    store.close();

    // Append partial, incomplete JSON bytes (no trailing newline) simulating mid-write process kill
    appendFileSync(journalPath, '{"index":1,"timestamp":12345,"action":"CRASHED_P', "utf8");

    // Also insert unflushed outbox row in SQLite that needs to be flushed
    const rawDb = new DatabaseSync(dbPath);
    rawDb.prepare(`
      INSERT INTO transactional_outbox (
        event_id, event_type, entity_type, entity_id, assessment_id, payload_json, created_at, flushed
      ) VALUES ('evt_recovered_001', 'POST_LEAD', 'lead', 'lead_rec', '${assessment1}', '{"status":"open"}', 2000, 0)
    `).run();
    rawDb.close();

    // Reopen store. Startup reconciliation should truncate partial trailing line and flush evt_recovered_001
    const reopenedStore = new SqlitePackBoardStore({
      dbPath,
      journalPath,
      assessmentId: assessment1,
    });

    const lines = readFileSync(journalPath, "utf8").trim().split("\n");
    expect(lines.length).toBe(2);

    const secondRecord = JSON.parse(lines[1]!) as AuditRecord;
    expect(secondRecord.event_id).toBe("evt_recovered_001");
    expect(secondRecord.index).toBe(1);

    const verifyRes = verifyAuditJournal(journalPath, reopenedStore.getKeyringManager().getKeyResolver());
    expect(verifyRes.ok).toBe(true);

    reopenedStore.close();
  });

  it("T04: fails closed when complete record has invalid HMAC and refuses to silently truncate", async () => {
    const lead1 = createDummyLead("secure1", "3".repeat(64));
    const lead2 = createDummyLead("secure2", "4".repeat(64));
    await store.postLead(lead1);
    await store.postLead(lead2);
    store.close();

    // Tamper with record 1 payload (complete record with newline, but corrupted HMAC)
    const original = readFileSync(journalPath, "utf8");
    const tampered = original.replace("secure1", "tampered_payload");
    writeFileSync(journalPath, tampered, "utf8");

    // Attempting to reopen store must FAIL CLOSED immediately
    expect(() => {
      new SqlitePackBoardStore({
        dbPath,
        journalPath,
        assessmentId: assessment1,
      });
    }).toThrow(/AUDIT_CHAIN_CORRUPTED/);
  });

  it("verifies full audit chain across versioned key rotations", async () => {
    // Post lead with Key v1
    const lead1 = createDummyLead("v1_lead", "5".repeat(64));
    await store.postLead(lead1);

    // Rotate Key to v2
    const rotateRes = await store.rotateHmacKey("rot_evt_alpha");
    expect(rotateRes.ok).toBe(true);
    if (!rotateRes.ok) return;
    expect(rotateRes.value.newVersion).toBe(2);

    // Post lead with Key v2
    const lead2 = createDummyLead("v2_lead", "6".repeat(64));
    await store.postLead(lead2);

    const lines = readFileSync(journalPath, "utf8").trim().split("\n");
    expect(lines.length).toBe(3);

    const r0 = JSON.parse(lines[0]!) as AuditRecord;
    const r1 = JSON.parse(lines[1]!) as AuditRecord;
    const r2 = JSON.parse(lines[2]!) as AuditRecord;

    expect(r0.action).toBe("POST_LEAD");
    expect(r0.key_version).toBe(1);

    expect(r1.action).toBe("KEY_ROTATION");
    expect(r1.key_version).toBe(1); // Rotation record signed by old key v1

    expect(r2.action).toBe("POST_LEAD");
    expect(r2.key_version).toBe(2); // New record signed by new key v2

    const verifyRes = verifyAuditJournal(journalPath, store.getKeyringManager().getKeyResolver());
    expect(verifyRes.ok).toBe(true);
  });
});
