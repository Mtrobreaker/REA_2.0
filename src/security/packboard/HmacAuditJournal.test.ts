import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  appendAuditRecord,
  verifyAuditJournal,
  GENESIS_HASH,
} from "./HmacAuditJournal.js";

describe("HmacAuditJournal", () => {
  let tempDir: string;
  let journalPath: string;
  const secret = "test-assessment-hmac-secret-12345";

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-audit-test-"));
    journalPath = join(tempDir, "packboard-audit.jsonl");
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  });

  it("appends records with valid initial genesis hash", () => {
    const res1 = appendAuditRecord(
      journalPath,
      secret,
      "POST_LEAD",
      "lead_1",
      "asm_1",
      { title: "Test Lead 1" },
    );
    expect(res1.ok).toBe(true);
    if (!res1.ok) return;

    expect(res1.value.index).toBe(0);
    expect(res1.value.prev_hash).toBe(GENESIS_HASH);

    const res2 = appendAuditRecord(
      journalPath,
      secret,
      "CLAIM_LEAD",
      "lead_1",
      "asm_1",
      { agent: "analyst-1" },
    );
    expect(res2.ok).toBe(true);
    if (!res2.ok) return;

    expect(res2.value.index).toBe(1);
    expect(res2.value.prev_hash).toBe(res1.value.entry_hash);

    const verifyRes = verifyAuditJournal(journalPath, secret);
    expect(verifyRes.ok).toBe(true);
  });

  it("detects tampering when payload is modified", () => {
    appendAuditRecord(journalPath, secret, "POST_LEAD", "lead_1", "asm_1", {
      title: "Initial",
    });
    appendAuditRecord(journalPath, secret, "CLAIM_LEAD", "lead_1", "asm_1", {
      agent: "analyst-1",
    });

    // Tamper with the first line
    const content = readFileSync(journalPath, "utf8");
    const tampered = content.replace("Initial", "HackedTitle");
    writeFileSync(journalPath, tampered, "utf8");

    const verifyRes = verifyAuditJournal(journalPath, secret);
    expect(verifyRes.ok).toBe(false);
    if (verifyRes.ok) return;
    expect(verifyRes.error.code).toBe("AUDIT_CHAIN_CORRUPTED");
    expect(verifyRes.error.line).toBe(1);
  });

  it("detects tampering when an entry is deleted or reordered", () => {
    appendAuditRecord(journalPath, secret, "ENTRY_0", "lead_1", "asm_1", {});
    appendAuditRecord(journalPath, secret, "ENTRY_1", "lead_1", "asm_1", {});
    appendAuditRecord(journalPath, secret, "ENTRY_2", "lead_1", "asm_1", {});

    // Delete middle entry
    const lines = readFileSync(journalPath, "utf8").trim().split("\n");
    const tamperedLines = [lines[0], lines[2]].join("\n") + "\n";
    writeFileSync(journalPath, tamperedLines, "utf8");

    const verifyRes = verifyAuditJournal(journalPath, secret);
    expect(verifyRes.ok).toBe(false);
    if (verifyRes.ok) return;
    expect(verifyRes.error.code).toBe("AUDIT_CHAIN_CORRUPTED");
  });
});

