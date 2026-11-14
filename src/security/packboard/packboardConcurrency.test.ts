import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SqlitePackBoardStore } from "./SqlitePackBoardStore.js";
import { verifyAuditJournal, type AuditRecord } from "./HmacAuditJournal.js";
import type { Lead, LeadClaim } from "../../domain/security/packboard/types.js";
import type { AssessmentId } from "../../domain/security/assessment.js";
import type { AssetId } from "../../domain/security/asset.js";

describe("PackBoard Concurrency: 50-Worker Parallel CAS Contention", () => {
  let tempDir: string;
  let dbPath: string;
  let journalPath: string;
  let store: SqlitePackBoardStore;

  const assessmentId = "asm_50worker_cas_contention_test_assessment_id_00000000000000000000" as AssessmentId;
  const assetId = "ast_50worker_cas_contention_test_asset_id_000000000000000000000000" as AssetId;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-cas-50-workers-"));
    dbPath = join(tempDir, "packboard.db");
    journalPath = join(tempDir, "packboard-audit.jsonl");
    store = new SqlitePackBoardStore({ dbPath, journalPath });
  });

  afterEach(() => {
    store.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup
    }
  });

  it("handles 50 parallel asynchronous workers contending for the same lead: exactly 1 succeeds, 49 get CAS_CONFLICT", async () => {
    // 1. Post a single initial lead with cas_version = 1
    const leadId = "lead_50worker00000000000000000000000000000000000000000000000000000000" as any;
    const initialLead: Lead = {
      id: leadId,
      assessment_id: assessmentId,
      fingerprint: "a".repeat(64),
      title: "Critical Contention Target",
      description: "Sink vulnerable to race condition",
      asset_id: assetId,
      location: {
        file: "src/concurrency/target.c",
        function: "handle_contention",
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
        cwe: ["CWE-362" as any],
        capec: [],
        mitre_attack: [],
        owasp: [],
      },
      severity: "CRITICAL",
      confidence: "CONFIRMED",
      status: "open",
      smoke_score: 1,
      cas_version: 1,
      provenance: "source_scan",
      claim: null,
      votes: [],
      evidence_hashes: [],
      created_at: Date.now(),
      updated_at: Date.now(),
    };

    const postRes = await store.postLead(initialLead);
    expect(postRes.ok).toBe(true);

    // 2. Launch 50 concurrent worker claims simultaneously, all with expectedVersion = 1
    const workerCount = 50;
    const workerPromises = Array.from({ length: workerCount }, async (_, index) => {
      const workerId = `worker_${index.toString().padStart(2, "0")}`;
      const claim: LeadClaim = {
        agent_id: workerId,
        host_id: "host_local",
        pid: 1000 + index,
        process_start_time: Date.now(),
        rea_run_id: `run_worker_${index}`,
        claimed_at: Date.now(),
        lease_until: Date.now() + 60000,
      };

      return store.claimLead(assessmentId, leadId, claim, 1);
    });

    const results = await Promise.all(workerPromises);

    // 3. Verify exactly 1 claim succeeded (ok: true)
    const successfulClaims = results.filter((r) => r.ok);
    const conflictedClaims = results.filter((r) => !r.ok);

    expect(successfulClaims.length).toBe(1);
    expect(conflictedClaims.length).toBe(workerCount - 1);

    // 4. Verify all 49 rejected workers received a typed CAS_CONFLICT with latest snapshot
    for (const failure of conflictedClaims) {
      if (failure.ok) continue;
      expect(failure.error.code).toBe("CAS_CONFLICT");
      if (failure.error.code === "CAS_CONFLICT") {
        expect(failure.error.expected_version).toBe(1);
        expect(failure.error.current_lead.cas_version).toBe(2);
        expect(failure.error.current_lead.status).toBe("claimed");
        expect(failure.error.current_lead.claim).not.toBeNull();
      }
    }

    // 5. Verify the persistent store reflects cas_version = 2 and the winning agent
    const finalLeadRes = await store.getLead(assessmentId, leadId);
    expect(finalLeadRes.ok).toBe(true);
    if (!finalLeadRes.ok) return;

    expect(finalLeadRes.value?.cas_version).toBe(2);
    expect(finalLeadRes.value?.status).toBe("claimed");
    const winningWorkerId = successfulClaims[0]?.ok ? (successfulClaims[0] as any).value.claim.agent_id : null;
    expect(finalLeadRes.value?.claim?.agent_id).toBe(winningWorkerId);
  });
});

describe("Cross-Process Journal Concurrency: Serialized Locking & Zero Forking", () => {
  let tempDir: string;
  let dbPath: string;
  let journalPath: string;
  const assessmentId = "asm_journal_concurrency_000000000000000000000000000000" as AssessmentId;
  const assetId = "ast_journal_concurrency_000000000000000000000000000000" as AssetId;
  const sharedSecret = "rea-shared-audit-secret-concurrency-test-64bytes".padEnd(64, "0");

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-journal-concurrency-"));
    dbPath = join(tempDir, "packboard.db");
    journalPath = join(tempDir, "packboard-audit.jsonl");
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("serializes concurrent writers through journal locking without creating competing or forked records", async () => {
    // Instantiate two independent store instances pointing to the exact same shared database and journal
    const storeA = new SqlitePackBoardStore({ dbPath, journalPath, hmacSecret: sharedSecret, assessmentId });
    const storeB = new SqlitePackBoardStore({ dbPath, journalPath, hmacSecret: sharedSecret, assessmentId });

    const totalLeadsPerStore = 10;
    const promises: Promise<any>[] = [];

    // Store A posts leads
    for (let i = 0; i < totalLeadsPerStore; i++) {
      const leadA: Lead = {
        id: `lead_storeA_${i.toString().padStart(4, "0")}`.padEnd(64, "0") as any,
        assessment_id: assessmentId,
        fingerprint: `fa_${i}`.padEnd(64, "0"),
        title: `Store A Lead ${i}`,
        description: "Store A concurrency test",
        asset_id: assetId,
        location: {
          file: "src/storeA.c",
          function: "funcA",
          line: i + 1,
          column: 1,
          end_line: i + 1,
          module: null,
          component: null,
          address: null,
          offset: null,
        },
        classification: { cve: [], cwe: [], capec: [], mitre_attack: [], owasp: [] },
        severity: "MEDIUM",
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
      };
      promises.push(storeA.postLead(leadA));
    }

    // Store B posts leads concurrently
    for (let i = 0; i < totalLeadsPerStore; i++) {
      const leadB: Lead = {
        id: `lead_storeB_${i.toString().padStart(4, "0")}`.padEnd(64, "0") as any,
        assessment_id: assessmentId,
        fingerprint: `fb_${i}`.padEnd(64, "0"),
        title: `Store B Lead ${i}`,
        description: "Store B concurrency test",
        asset_id: assetId,
        location: {
          file: "src/storeB.c",
          function: "funcB",
          line: i + 1,
          column: 1,
          end_line: i + 1,
          module: null,
          component: null,
          address: null,
          offset: null,
        },
        classification: { cve: [], cwe: [], capec: [], mitre_attack: [], owasp: [] },
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
      };
      promises.push(storeB.postLead(leadB));
    }

    const results = await Promise.all(promises);
    for (const r of results) {
      expect(r.ok).toBe(true);
    }

    storeA.close();
    storeB.close();

    // Verify journal file on disk
    const content = readFileSync(journalPath, "utf8").trim();
    const lines = content.split("\n");
    expect(lines.length).toBe(totalLeadsPerStore * 2);

    // Verify every record's index is strictly sequential 0..19 without gaps or duplicates
    const records = lines.map((l) => JSON.parse(l) as AuditRecord);
    for (let idx = 0; idx < records.length; idx++) {
      expect(records[idx]?.index).toBe(idx);
      if (idx > 0) {
        expect(records[idx]?.prev_hash).toBe(records[idx - 1]?.entry_hash);
      }
    }

    // Verify full cryptographic verification passes
    const verifyRes = verifyAuditJournal(journalPath, sharedSecret);
    expect(verifyRes.ok).toBe(true);
  });
});
