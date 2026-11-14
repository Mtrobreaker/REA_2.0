import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir, hostname } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { SqlitePackBoardStore } from "./SqlitePackBoardStore.js";
import { verifyAuditJournal } from "./HmacAuditJournal.js";
import { acquireJournalLockSync, type JournalLockPayload } from "./JournalLock.js";
import type { Lead, LeadClaim } from "../../domain/security/packboard/types.js";
import type { AssessmentId } from "../../domain/security/assessment.js";
import type { AssetId } from "../../domain/security/asset.js";

const assessmentId = "asm_crash_recovery_test_assessment_id_000000000000000000000000" as AssessmentId;
const assetId = "ast_crash_recovery_test_asset_id_000000000000000000000000000" as AssetId;
const hmacSecret = "rea-crash-recovery-secret-test-999";

const createBaseLead = (id: any, title: string): Lead => ({
  id,
  assessment_id: assessmentId,
  fingerprint: id.slice(5).padEnd(64, "0"),
  title,
  description: "Description",
  asset_id: assetId,
  location: {
    file: "src/driver.c",
    function: "ioctl_handler",
    line: 25,
    column: 1,
    end_line: 25,
    module: null,
    component: null,
    address: null,
    offset: null,
  },
  classification: {
    cve: [],
    cwe: ["CWE-20" as any],
    capec: [],
    mitre_attack: [],
    owasp: [],
  },
  severity: "HIGH",
  confidence: "CONFIRMED",
  status: "open",
  smoke_score: 1,
  cas_version: 1,
  provenance: "firmware_extraction",
  claim: null,
  votes: [],
  evidence_hashes: [],
  created_at: Date.now(),
  updated_at: Date.now(),
});

describe("PackBoard Fault Tolerance: Crash Recovery", () => {
  let tempDir: string;
  let dbPath: string;
  let journalPath: string;
  let store: SqlitePackBoardStore;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-crash-recovery-"));
    dbPath = join(tempDir, "packboard.db");
    journalPath = join(tempDir, "packboard-audit.jsonl");
    store = new SqlitePackBoardStore({ dbPath, journalPath, hmacSecret });
  });

  afterEach(() => {
    store.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup
    }
  });

  it("safely reaps crashed worker's expired lease and preserves active worker's lease", async () => {
    const lead1Id = "lead_crashed0000000000000000000000000000000000000000000000000000000" as any;
    const lead2Id = "lead_survivor000000000000000000000000000000000000000000000000000000" as any;

    await store.postLead(createBaseLead(lead1Id, "Worker 1 Lead (To be crashed)"));
    await store.postLead(createBaseLead(lead2Id, "Worker 2 Lead (Active survivor)"));

    const now = Date.now();
    const crashedClaim: LeadClaim = {
      agent_id: "crashed_worker",
      host_id: "host_local",
      pid: 8888,
      process_start_time: now,
      rea_run_id: "run_crashed",
      claimed_at: now,
      lease_until: now + 50,
    };

    const activeClaim: LeadClaim = {
      agent_id: "active_worker",
      host_id: "host_local",
      pid: 9999,
      process_start_time: now,
      rea_run_id: "run_active",
      claimed_at: now,
      lease_until: now + 60000,
    };

    await store.claimLead(assessmentId, lead1Id, crashedClaim, 1);
    await store.claimLead(assessmentId, lead2Id, activeClaim, 1);

    await new Promise((resolve) => setTimeout(resolve, 75));

    const reapRes = await store.reapExpiredLeases(assessmentId, Date.now());
    expect(reapRes.ok).toBe(true);
    if (!reapRes.ok) return;
    expect(reapRes.value).toBe(1);

    const lead1After = await store.getLead(assessmentId, lead1Id);
    expect(lead1After.ok).toBe(true);
    if (!lead1After.ok) return;
    expect(lead1After.value?.status).toBe("open");
    expect(lead1After.value?.cas_version).toBe(3);

    const lead2After = await store.getLead(assessmentId, lead2Id);
    expect(lead2After.ok).toBe(true);
    if (!lead2After.ok) return;
    expect(lead2After.value?.status).toBe("claimed");
    expect(lead2After.value?.claim?.agent_id).toBe("active_worker");
  });
});

describe("PackBoard Fault Tolerance: Process Restart & Stale Lock Recovery", () => {
  let tempDir: string;
  let dbPath: string;
  let journalPath: string;
  let store: SqlitePackBoardStore;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-restart-recovery-"));
    dbPath = join(tempDir, "packboard.db");
    journalPath = join(tempDir, "packboard-audit.jsonl");
    store = new SqlitePackBoardStore({ dbPath, journalPath, hmacSecret });
  });

  afterEach(() => {
    store.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup
    }
  });

  it("survives application crash / restart with 100% database and HMAC audit integrity", async () => {
    const leadId = "lead_restart0000000000000000000000000000000000000000000000000000000" as any;
    const testLead = createBaseLead(leadId, "Restart Persistence Target");

    await store.postLead(testLead);
    store.close();

    const restartedStore = new SqlitePackBoardStore({
      dbPath,
      journalPath,
      hmacSecret,
    });

    const recovered = await restartedStore.getLead(assessmentId, leadId);
    expect(recovered.ok).toBe(true);
    if (!recovered.ok) return;

    expect(recovered.value?.id).toBe(leadId);
    expect(recovered.value?.title).toBe("Restart Persistence Target");
    expect(recovered.value?.cas_version).toBe(1);

    const verifyRes = verifyAuditJournal(journalPath, hmacSecret);
    expect(verifyRes.ok).toBe(true);

    restartedStore.close();
  });

  it("safely reclaims a stale journal lock left behind by a crashed process and resumes outbox operations", async () => {
    // 1. Post initial lead
    const lead1Id = "lead_stale_lock_1000000000000000000000000000000000000000000000000000" as any;
    await store.postLead(createBaseLead(lead1Id, "Initial Lead Before Lock Crash"));
    store.close();

    // 2. Simulate crash leaving a stale .lock file from deceased PID 999999
    const lockPath = `${journalPath}.lock`;
    const staleLock: JournalLockPayload = {
      lockId: "crashed-pid-999999-lock",
      pid: 999999,
      hostname: hostname(),
      acquiredAt: Date.now() - 5000,
      expiresAt: Date.now() + 60000,
    };
    writeFileSync(lockPath, JSON.stringify(staleLock), "utf8");
    expect(existsSync(lockPath)).toBe(true);

    // 3. Inject an unflushed outbox record into SQLite simulating mid-crash state
    const rawDb = new DatabaseSync(dbPath);
    rawDb.prepare(`
      INSERT INTO transactional_outbox (
        event_id, event_type, entity_type, entity_id, assessment_id, payload_json, created_at, flushed
      ) VALUES (?, 'POST_LEAD', 'lead', ?, ?, ?, ?, 0)
    `).run(
      "evt_crash_recovery_unflushed_001",
      "lead_crashed_recovery_unflushed",
      assessmentId,
      JSON.stringify({ title: "Unflushed Mid-Crash Lead" }),
      Date.now(),
    );
    rawDb.close();

    // 4. Reopen the store. Startup reconciliation runs!
    // It should detect the stale lock, safely reclaim it, flush the outbox, and update SQLite flushed = 1.
    const restartedStore = new SqlitePackBoardStore({
      dbPath,
      journalPath,
      hmacSecret,
    });

    // Check that lock was released after reconciliation
    expect(existsSync(lockPath)).toBe(false);

    // Verify outbox was flushed to 1
    const verifyDb = new DatabaseSync(dbPath);
    const row = verifyDb.prepare(
      "SELECT * FROM transactional_outbox WHERE event_id = 'evt_crash_recovery_unflushed_001'",
    ).get() as any;
    verifyDb.close();

    expect(row).toBeDefined();
    expect(row.flushed).toBe(1);

    // Verify journal cryptographic integrity
    const verifyRes = verifyAuditJournal(journalPath, hmacSecret);
    expect(verifyRes.ok).toBe(true);

    restartedStore.close();
  });

  it("prevents competing recovery processes from becoming simultaneous owners", () => {
    const lockPath = `${journalPath}.lock`;
    // Create an active lock owned by a foreign process
    const foreignLock: JournalLockPayload = {
      lockId: "foreign-active-lock-uuid",
      pid: process.pid,
      hostname: "foreign-host-worker-node",
      acquiredAt: Date.now(),
      expiresAt: Date.now() + 60000,
    };
    writeFileSync(lockPath, JSON.stringify(foreignLock), "utf8");
    expect(existsSync(lockPath)).toBe(true);

    // Second process attempting to acquire while actively held by foreign process must timeout
    expect(() => {
      acquireJournalLockSync(journalPath, {
        timeoutMs: 100,
        retryDelayMinMs: 10,
        retryDelayMaxMs: 25,
      });
    }).toThrow(/JOURNAL_LOCK_TIMEOUT/);

    // Clean up
    rmSync(lockPath, { force: true });

    // Now acquisition succeeds cleanly
    const lockB = acquireJournalLockSync(journalPath);
    expect(existsSync(lockPath)).toBe(true);
    lockB.release();
    expect(existsSync(lockPath)).toBe(false);
  });
});
