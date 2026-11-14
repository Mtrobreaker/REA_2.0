import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SqlitePackBoardStore } from "./SqlitePackBoardStore.js";
import type { Lead, LeadClaim } from "../../domain/security/packboard/types.js";
import type { AssessmentId } from "../../domain/security/assessment.js";
import type { AssetId } from "../../domain/security/asset.js";

const assessment1 = "asm_1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff" as AssessmentId;
const assessment2 = "asm_9999888877776666555544443333222211110000ffffeeeeddddccccbbbbaaaa" as AssessmentId;
const asset1 = "ast_1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff" as AssetId;

const createDummyLead = (id: string, fingerprint: string, asmId = assessment1): Lead => ({
  id: `lead_${id.padEnd(64, "0")}` as any,
  assessment_id: asmId,
  fingerprint,
  title: `Vulnerability ${id}`,
  description: `Description ${id}`,
  asset_id: asset1,
  location: {
    file: "src/main.c",
    function: "process_input",
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
  confidence: "MEDIUM",
  status: "open",
  smoke_score: 1,
  cas_version: 1,
  provenance: "source_scan",
  claim: null,
  votes: [],
  evidence_hashes: ["sha256_evidence_1"],
  created_at: 1000,
  updated_at: 1000,
});

const createDummyClaim = (agentId: string, ttlSeconds = 60): LeadClaim => ({
  agent_id: agentId,
  host_id: "host_local",
  pid: 1234,
  process_start_time: 100000,
  rea_run_id: "run_alpha",
  claimed_at: Date.now(),
  lease_until: Date.now() + ttlSeconds * 1000,
});

describe("SqlitePackBoardStore: Basic & Concurrency Operations", () => {
  let tempDir: string;
  let dbPath: string;
  let journalPath: string;
  let store: SqlitePackBoardStore;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-packboard-test-"));
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

  it("stores and retrieves a lead", async () => {
    const lead = createDummyLead("a", "f".repeat(64));
    const postRes = await store.postLead(lead);
    expect(postRes.ok).toBe(true);

    const getRes = await store.getLead(assessment1, lead.id);
    expect(getRes.ok).toBe(true);
    if (!getRes.ok) return;
    expect(getRes.value?.id).toBe(lead.id);
    expect(getRes.value?.status).toBe("open");
  });

  it("monotonically corroborates identical fingerprint with smoke score upgrade", async () => {
    const fp = "f".repeat(64);
    const lead1 = createDummyLead("a", fp);
    const lead2 = createDummyLead("b", fp);

    const post1 = await store.postLead(lead1);
    expect(post1.ok).toBe(true);

    const post2 = await store.postLead(lead2);
    expect(post2.ok).toBe(true);
    if (!post2.ok) return;

    expect(post2.value.id).toBe(lead1.id);
    expect(post2.value.smoke_score).toBe(2);

    const listRes = await store.listLeads(assessment1);
    expect(listRes.ok).toBe(true);
    if (!listRes.ok) return;
    expect(listRes.value.length).toBe(1);
  });

  it("enforces CAS concurrency: two claims on same version yields 1 success and 1 conflict", async () => {
    const lead = createDummyLead("a", "f".repeat(64));
    await store.postLead(lead);

    const claim1 = createDummyClaim("agent_1");
    const claim2 = createDummyClaim("agent_2");

    const res1 = await store.claimLead(assessment1, lead.id, claim1, 1);
    const res2 = await store.claimLead(assessment1, lead.id, claim2, 1);

    expect(res1.ok).toBe(true);
    expect(res2.ok).toBe(false);

    if (!res2.ok) {
      expect(res2.error.code).toBe("CAS_CONFLICT");
      if (res2.error.code === "CAS_CONFLICT") {
        expect(res2.error.current_lead.status).toBe("claimed");
        expect(res2.error.current_lead.claim?.agent_id).toBe("agent_1");
        expect(res2.error.current_lead.cas_version).toBe(2);
      }
    }
  });
});

describe("SqlitePackBoardStore: Lease & Session Management", () => {
  let tempDir: string;
  let dbPath: string;
  let journalPath: string;
  let store: SqlitePackBoardStore;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-packboard-lease-test-"));
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

  it("extends an active lease for the claimant agent", async () => {
    const lead = createDummyLead("a", "f".repeat(64));
    await store.postLead(lead);

    const claim = createDummyClaim("agent_1", 30);
    const claimRes = await store.claimLead(assessment1, lead.id, claim, 1);
    expect(claimRes.ok).toBe(true);

    const extendRes = await store.extendLease(assessment1, lead.id, claim, 60);
    expect(extendRes.ok).toBe(true);
    if (!extendRes.ok) return;
    expect(extendRes.value.claim?.lease_until).toBeGreaterThan(claim.lease_until);
  });

  it("reaps expired leases while preserving active ones", async () => {
    const leadExpired = createDummyLead("1", "1".repeat(64));
    const leadActive = createDummyLead("2", "2".repeat(64));

    await store.postLead(leadExpired);
    await store.postLead(leadActive);

    const now = Date.now();
    const claimExpired: LeadClaim = {
      agent_id: "agent_dead",
      host_id: "host_local",
      pid: 9999,
      process_start_time: 1000,
      rea_run_id: "run_old",
      claimed_at: now - 30000,
      lease_until: now - 10000,
    };
    const claimActive = createDummyClaim("agent_live", 60);

    await store.claimLead(assessment1, leadExpired.id, claimExpired, 1);
    await store.claimLead(assessment1, leadActive.id, claimActive, 1);

    const reapRes = await store.reapExpiredLeases(assessment1, now);
    expect(reapRes.ok).toBe(true);
    if (!reapRes.ok) return;
    expect(reapRes.value).toBe(1);

    const lead1After = await store.getLead(assessment1, leadExpired.id);
    expect(lead1After.ok).toBe(true);
    if (!lead1After.ok) return;
    expect(lead1After.value?.status).toBe("open");

    const lead2After = await store.getLead(assessment1, leadActive.id);
    expect(lead2After.ok).toBe(true);
    if (!lead2After.ok) return;
    expect(lead2After.value?.status).toBe("claimed");
  });

  it("strictly isolates leads across assessment sessions", async () => {
    const lead1 = createDummyLead("a", "f".repeat(64), assessment1);
    const lead2 = createDummyLead("b", "f".repeat(64), assessment2);

    await store.postLead(lead1);
    await store.postLead(lead2);

    const list1 = await store.listLeads(assessment1);
    expect(list1.ok).toBe(true);
    if (!list1.ok) return;
    expect(list1.value.length).toBe(1);
    expect(list1.value[0]?.assessment_id).toBe(assessment1);

    const list2 = await store.listLeads(assessment2);
    expect(list2.ok).toBe(true);
    if (!list2.ok) return;
    expect(list2.value.length).toBe(1);
    expect(list2.value[0]?.assessment_id).toBe(assessment2);
  });
});
