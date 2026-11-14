import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir, hostname } from "node:os";
import { join } from "node:path";
import { acquireJournalLockSync, releaseJournalLockSync, type JournalLockPayload } from "./JournalLock.js";

describe("JournalLock: Cross-Process Mutual Exclusion & Stale Recovery", () => {
  let tempDir: string;
  let journalPath: string;
  let lockPath: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-journal-lock-test-"));
    journalPath = join(tempDir, "audit.jsonl");
    lockPath = `${journalPath}.lock`;
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("acquires exclusive lock, writes payload, and deletes lock on release", () => {
    expect(existsSync(lockPath)).toBe(false);

    const lock = acquireJournalLockSync(journalPath);
    expect(existsSync(lockPath)).toBe(true);

    const content = JSON.parse(readFileSync(lockPath, "utf8")) as JournalLockPayload;
    expect(content.lockId).toBe(lock.lockId);
    expect(content.pid).toBe(process.pid);
    expect(content.hostname).toBe(hostname());

    lock.release();
    expect(existsSync(lockPath)).toBe(false);
  });

  it("supports in-process re-entrancy without deadlocking", () => {
    const lock1 = acquireJournalLockSync(journalPath);
    expect(existsSync(lockPath)).toBe(true);

    // Re-entrant acquisition
    const lock2 = acquireJournalLockSync(journalPath);
    expect(lock2.lockId).toBe(lock1.lockId);

    // First release decrements depth
    lock2.release();
    expect(existsSync(lockPath)).toBe(true);

    // Final release removes lock file
    lock1.release();
    expect(existsSync(lockPath)).toBe(false);
  });

  it("recovers stale lock from a dead PID on current host", () => {
    // Write a lock file with a non-existent PID (999999)
    const deadPayload: JournalLockPayload = {
      lockId: "dead-lock-id-12345",
      pid: 999999,
      hostname: hostname(),
      acquiredAt: Date.now() - 5000,
      expiresAt: Date.now() + 60000, // Even if unexpired, process is dead
    };
    writeFileSync(lockPath, JSON.stringify(deadPayload), "utf8");
    expect(existsSync(lockPath)).toBe(true);

    // New acquisition detects process is dead and reclaims lock safely
    const lock = acquireJournalLockSync(journalPath, { timeoutMs: 2000 });
    expect(lock.lockId).not.toBe(deadPayload.lockId);

    const newPayload = JSON.parse(readFileSync(lockPath, "utf8")) as JournalLockPayload;
    expect(newPayload.lockId).toBe(lock.lockId);
    expect(newPayload.pid).toBe(process.pid);

    lock.release();
    expect(existsSync(lockPath)).toBe(false);
  });

  it("recovers stale lock whose lease has expired", () => {
    // Write a lock file with an expired timestamp
    const expiredPayload: JournalLockPayload = {
      lockId: "expired-lock-id-99999",
      pid: 1, // System init process (might exist on POSIX, but lease expired)
      hostname: "remote-or-other-host",
      acquiredAt: Date.now() - 20000,
      expiresAt: Date.now() - 1000, // Expired 1 second ago
    };
    writeFileSync(lockPath, JSON.stringify(expiredPayload), "utf8");

    const lock = acquireJournalLockSync(journalPath, { timeoutMs: 2000 });
    expect(lock.lockId).not.toBe(expiredPayload.lockId);

    lock.release();
    expect(existsSync(lockPath)).toBe(false);
  });

  it("times out if active lock is held by a live process with unexpired lease", () => {
    // Write an active lock file with current live PID and future lease, but different lockId
    const activePayload: JournalLockPayload = {
      lockId: "foreign-active-lock-id",
      pid: process.pid,
      hostname: "different-host-simulation",
      acquiredAt: Date.now(),
      expiresAt: Date.now() + 60000,
    };
    writeFileSync(lockPath, JSON.stringify(activePayload), "utf8");

    expect(() => {
      acquireJournalLockSync(journalPath, {
        timeoutMs: 150,
        retryDelayMinMs: 10,
        retryDelayMaxMs: 20,
      });
    }).toThrow(/JOURNAL_LOCK_TIMEOUT/);

    // Clean up
    try {
      rmSync(lockPath, { force: true });
    } catch {
      // Ignore
    }
  });
});

