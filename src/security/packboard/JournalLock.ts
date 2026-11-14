import { openSync, writeSync, fsyncSync, closeSync, unlinkSync, readFileSync, renameSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { hostname } from "node:os";
import { randomUUID } from "node:crypto";

export interface JournalLockPayload {
  readonly lockId: string;
  readonly pid: number;
  readonly hostname: string;
  readonly acquiredAt: number;
  readonly expiresAt: number;
}

export interface JournalLockOptions {
  /** Maximum duration (ms) the lock is held before being considered expired. Default: 15,000ms */
  readonly leaseMs?: number | undefined;
  /** Maximum duration (ms) to wait for lock acquisition before timing out. Default: 15,000ms */
  readonly timeoutMs?: number | undefined;
  /** Minimum sleep delay (ms) between retries. Default: 15ms */
  readonly retryDelayMinMs?: number | undefined;
  /** Maximum sleep delay (ms) between retries. Default: 45ms */
  readonly retryDelayMaxMs?: number | undefined;
}

export interface JournalLockHandle {
  readonly lockId: string;
  readonly journalPath: string;
  readonly lockPath: string;
  release: () => void;
}

// In-process tracking for re-entrancy within the same process thread
const inProcessLocks = new Map<string, { lockId: string; depth: number }>();

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error: any) {
    if (error?.code === "ESRCH") {
      return false;
    }
    // EPERM means process exists but we lack permission to signal it (still alive)
    return true;
  }
}

function syncSleep(ms: number): void {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    // Synchronous busy-spin wait
  }
}

/**
 * Acquires a cross-process exclusive lock for the given journal path.
 *
 * Implements:
 * 1. Kernel-level atomic lock file creation via O_CREAT | O_EXCL.
 * 2. In-process re-entrancy to prevent self-deadlocks.
 * 3. Safe stale lock recovery:
 *    - Reclaims locks held by deceased processes (ESRCH) on the current host.
 *    - Reclaims locks whose lease duration has expired.
 *    - Uses atomic renameSync to prevent two competing recovery processes from becoming simultaneous owners.
 * 4. Safe release: only deletes the lock file if this handle's lockId matches.
 */
export function acquireJournalLockSync(
  journalPath: string,
  options?: JournalLockOptions,
): JournalLockHandle {
  const lockPath = `${journalPath}.lock`;
  const normalizedKey = lockPath.toLowerCase();

  // 1. In-process re-entrancy
  const inProcess = inProcessLocks.get(normalizedKey);
  if (inProcess) {
    inProcess.depth++;
    return {
      lockId: inProcess.lockId,
      journalPath,
      lockPath,
      release: () => releaseJournalLockSync(lockPath, inProcess.lockId),
    };
  }

  const leaseMs = options?.leaseMs ?? 15_000;
  const timeoutMs = options?.timeoutMs ?? 15_000;
  const retryMin = options?.retryDelayMinMs ?? 15;
  const retryMax = options?.retryDelayMaxMs ?? 45;

  const parentDir = dirname(lockPath);
  if (!existsSync(parentDir)) {
    mkdirSync(parentDir, { recursive: true });
  }

  const startTime = Date.now();
  const currentHost = hostname();

  while (Date.now() - startTime <= timeoutMs) {
    const lockId = randomUUID();
    const now = Date.now();
    const payload: JournalLockPayload = {
      lockId,
      pid: process.pid,
      hostname: currentHost,
      acquiredAt: now,
      expiresAt: now + leaseMs,
    };

    let fd: number | undefined;
    try {
      // Atomic lock creation: fails with EEXIST if lock file already exists
      fd = openSync(lockPath, "wx");
      writeSync(fd, JSON.stringify(payload), undefined, "utf8");
      fsyncSync(fd);
      closeSync(fd);
      fd = undefined;

      inProcessLocks.set(normalizedKey, { lockId, depth: 1 });

      return {
        lockId,
        journalPath,
        lockPath,
        release: () => releaseJournalLockSync(lockPath, lockId),
      };
    } catch (err: any) {
      if (fd !== undefined) {
        try {
          closeSync(fd);
        } catch {
          // Ignore
        }
      }

      if (err?.code !== "EEXIST") {
        throw err;
      }

      // Lock file already exists. Inspect for staleness.
      let isStale = false;
      let existingPayload: JournalLockPayload | undefined;

      try {
        if (existsSync(lockPath)) {
          const raw = readFileSync(lockPath, "utf8").trim();
          if (raw.length > 0) {
            existingPayload = JSON.parse(raw) as JournalLockPayload;
          } else {
            // Empty lock file left behind by abrupt crash
            isStale = true;
          }
        }
      } catch {
        // Partial write or locked file - retry after delay
      }

      if (existingPayload) {
        const expired = Date.now() > existingPayload.expiresAt;
        const processDead =
          existingPayload.hostname === currentHost && !isProcessAlive(existingPayload.pid);

        if (expired || processDead) {
          isStale = true;
        }
      }

      if (isStale) {
        // Attempt atomic stale lock recovery using unique rename token.
        // If two processes detect staleness simultaneously, exactly ONE will succeed renameSync.
        const staleToken = `${lockPath}.stale.${randomUUID()}`;
        let stolen = false;
        try {
          renameSync(lockPath, staleToken);
          stolen = true;
        } catch {
          stolen = false;
        }

        if (stolen) {
          try {
            unlinkSync(staleToken);
          } catch {
            // Ignore
          }
          // The stale lock was atomically removed; retry acquisition immediately
          continue;
        }
      }

      // Jittered sleep before retry
      const jitter = Math.floor(Math.random() * (retryMax - retryMin) + retryMin);
      syncSleep(jitter);
    }
  }

  throw new Error(`JOURNAL_LOCK_TIMEOUT: Timed out after ${timeoutMs}ms waiting to acquire lock on ${journalPath}`);
}

export function releaseJournalLockSync(lockPath: string, lockId: string): void {
  const normalizedKey = lockPath.toLowerCase();
  const inProcess = inProcessLocks.get(normalizedKey);

  if (inProcess) {
    if (inProcess.lockId !== lockId) {
      // Not our lockId
      return;
    }
    inProcess.depth--;
    if (inProcess.depth > 0) {
      return; // Still held by outer in-process caller
    }
    inProcessLocks.delete(normalizedKey);
  }

  try {
    if (existsSync(lockPath)) {
      const raw = readFileSync(lockPath, "utf8").trim();
      if (raw.length > 0) {
        const payload = JSON.parse(raw) as JournalLockPayload;
        if (payload.lockId === lockId) {
          unlinkSync(lockPath);
        }
      }
    }
  } catch {
    // Ignore cleanup errors during release
  }
}

