import type { DatabaseSync } from "node:sqlite";
import { existsSync, readFileSync, openSync, fsyncSync, closeSync, appendFileSync } from "node:fs";
import { ok, err, type Result } from "../../domain/result.js";
import {
  computeEntryHash,
  truncateIncompleteTrailingLine,
  verifyAuditJournal,
  GENESIS_HASH,
  type AuditRecord,
  type KeyResolver,
} from "./HmacAuditJournal.js";
import { acquireJournalLockSync } from "./JournalLock.js";
import type { SqliteOutboxRow } from "./SqlitePackBoardSchema.js";

export interface OutboxReconciliationResult {
  readonly flushedCount: number;
  readonly alreadyCommittedCount: number;
  readonly truncatedBytes: number;
}

export class OutboxFlusher {
  private readonly db: DatabaseSync;
  private readonly journalPath: string;
  private readonly keyResolver: KeyResolver;
  private readonly getActiveKey: () => { version: number; key_hex: string };

  constructor(
    db: DatabaseSync,
    journalPath: string,
    keyResolver: KeyResolver,
    getActiveKey: () => { version: number; key_hex: string },
  ) {
    this.db = db;
    this.journalPath = journalPath;
    this.keyResolver = keyResolver;
    this.getActiveKey = getActiveKey;
  }

  /**
   * Reads and validates the current state of the audit journal from disk.
   */
  private readCurrentJournalState(): {
    readonly lastEntryHash: string | undefined;
    readonly lastIndex: number | undefined;
    readonly committedEventIds: Set<string>;
  } {
    const committedEventIds = new Set<string>();
    let lastEntryHash: string | undefined;
    let lastIndex: number | undefined;

    if (existsSync(this.journalPath)) {
      const content = readFileSync(this.journalPath, "utf8").trim();
      if (content.length > 0) {
        const lines = content.split("\n");
        for (const line of lines) {
          if (!line) continue;
          try {
            const parsed = JSON.parse(line) as AuditRecord;
            if (parsed.event_id) {
              committedEventIds.add(parsed.event_id);
            }
            lastEntryHash = parsed.entry_hash;
            lastIndex = parsed.index;
          } catch {
            // Ignore incomplete trailing line
          }
        }
      }
    }

    return { lastEntryHash, lastIndex, committedEventIds };
  }

  /**
   * Reconciles the transactional outbox against the append-only audit journal upon startup.
   * Serializes the operation under cross-process journal lock:
   * 1. Acquire lock.
   * 2. Detects and truncates any incomplete trailing line caused by crash mid-write.
   * 3. Verifies complete cryptographic HMAC chain of the journal.
   * 4. Reconciles unflushed outbox entries against committed journal event IDs.
   * 5. Flushes pending records and updates SQLite outbox.
   * 6. Releases lock.
   */
  public reconcileOnStartup(): Result<OutboxReconciliationResult, Error> {
    const lockHandle = acquireJournalLockSync(this.journalPath);
    try {
      let truncatedBytes = 0;

      if (existsSync(this.journalPath)) {
        // Step 1: Incomplete line recovery
        const truncRes = truncateIncompleteTrailingLine(this.journalPath);
        if (!truncRes.ok) {
          return err(truncRes.error);
        }
        truncatedBytes = truncRes.value.bytesRemoved;

        // Step 2: Strict cryptographic verification
        const verifyRes = verifyAuditJournal(this.journalPath, this.keyResolver);
        if (!verifyRes.ok) {
          return err(
            new Error(
              `AUDIT_CHAIN_CORRUPTED at line ${verifyRes.error.line}: ${verifyRes.error.reason}`,
            ),
          );
        }
      }

      // Step 3: Collect committed event IDs and find last known hash
      const state = this.readCurrentJournalState();
      const committedEventIds = new Set<string>(state.committedEventIds);
      let lastKnownHash = state.lastEntryHash;
      let lastKnownIndex = state.lastIndex;

      // Step 4: Reconcile unflushed outbox rows
      const stmt = this.db.prepare(
        "SELECT * FROM transactional_outbox WHERE flushed = 0 ORDER BY outbox_id ASC",
      );
      const rows = stmt.all() as unknown as ReadonlyArray<SqliteOutboxRow>;

      const updateStmt = this.db.prepare(
        "UPDATE transactional_outbox SET flushed = 1 WHERE outbox_id = ?",
      );

      let flushedCount = 0;
      let alreadyCommittedCount = 0;

      for (const row of rows) {
        if (committedEventIds.has(row.event_id)) {
          // Crash window case: Event was written and fsynced to disk, but SQLite update hadn't run
          updateStmt.run(row.outbox_id);
          alreadyCommittedCount++;
        } else {
          // Event needs to be flushed to journal
          const activeKey = this.getActiveKey();
          let payload: unknown = {};
          try {
            payload = JSON.parse(row.payload_json);
          } catch {
            payload = { raw: row.payload_json };
          }

          let signingKeyHex = activeKey.key_hex;
          let signingVersion = activeKey.version;
          if (
            row.event_type === "KEY_ROTATION" &&
            typeof payload === "object" &&
            payload !== null &&
            "old_key_version" in payload
          ) {
            const oldVersion = Number((payload as any).old_key_version);
            const resolved =
              typeof this.keyResolver === "function"
                ? this.keyResolver(oldVersion)
                : typeof this.keyResolver === "string"
                  ? this.keyResolver
                  : this.keyResolver.get(oldVersion);
            if (resolved) {
              signingKeyHex = resolved;
              signingVersion = oldVersion;
            }
          }

          const nextIndex = lastKnownIndex !== undefined ? lastKnownIndex + 1 : 0;
          const prevHash = lastKnownHash ?? GENESIS_HASH;
          const timestamp = Date.now();

          const entryHash = computeEntryHash(
            signingKeyHex,
            nextIndex,
            timestamp,
            row.event_type,
            row.entity_id,
            row.assessment_id,
            payload,
            prevHash,
            row.event_id,
            signingVersion,
          );

          const record: AuditRecord = {
            index: nextIndex,
            timestamp,
            action: row.event_type,
            event_id: row.event_id,
            lead_id: row.entity_id,
            assessment_id: row.assessment_id,
            payload,
            prev_hash: prevHash,
            key_version: signingVersion,
            entry_hash: entryHash,
          };

          appendFileSync(this.journalPath, JSON.stringify(record) + "\n", "utf8");
          this.syncFile();

          lastKnownHash = record.entry_hash;
          lastKnownIndex = record.index;
          committedEventIds.add(row.event_id);

          updateStmt.run(row.outbox_id);
          flushedCount++;
        }
      }

      return ok({
        flushedCount,
        alreadyCommittedCount,
        truncatedBytes,
      });
    } catch (cause) {
      return err(cause instanceof Error ? cause : new Error(String(cause)));
    } finally {
      lockHandle.release();
    }
  }

  /**
   * Synchronously flushes all pending outbox records to the audit journal and marks them flushed.
   *
   * Serializes the entire operation per specification:
   * 1. Acquire the lock.
   * 2. Validate/read the current journal state.
   * 3. Determine the previous hash.
   * 4. Generate the HMAC record.
   * 5. Append the record.
   * 6. fsync the journal.
   * 7. Update the SQLite outbox.
   * 8. Release the lock.
   */
  public drainOutbox(): Result<number, Error> {
    try {
      const stmt = this.db.prepare(
        "SELECT * FROM transactional_outbox WHERE flushed = 0 ORDER BY outbox_id ASC",
      );
      const rows = stmt.all() as unknown as ReadonlyArray<SqliteOutboxRow>;
      if (rows.length === 0) {
        return ok(0);
      }

      const updateStmt = this.db.prepare(
        "UPDATE transactional_outbox SET flushed = 1 WHERE outbox_id = ?",
      );

      let count = 0;
      for (const row of rows) {
        // Step 1: Acquire the lock
        const lockHandle = acquireJournalLockSync(this.journalPath);
        try {
          // Step 2: Validate/read the current journal state
          truncateIncompleteTrailingLine(this.journalPath);
          const state = this.readCurrentJournalState();

          if (state.committedEventIds.has(row.event_id)) {
            // Already committed to journal (e.g. from crash window or concurrent process)
            updateStmt.run(row.outbox_id);
            continue;
          }

          // Step 3: Determine the previous hash and next index
          const prevHash = state.lastEntryHash ?? GENESIS_HASH;
          const nextIndex = state.lastIndex !== undefined ? state.lastIndex + 1 : 0;

          // Step 4: Generate the HMAC record
          const activeKey = this.getActiveKey();
          let payload: unknown = {};
          try {
            payload = JSON.parse(row.payload_json);
          } catch {
            payload = { raw: row.payload_json };
          }

          let signingKeyHex = activeKey.key_hex;
          let signingVersion = activeKey.version;
          if (
            row.event_type === "KEY_ROTATION" &&
            typeof payload === "object" &&
            payload !== null &&
            "old_key_version" in payload
          ) {
            const oldVersion = Number((payload as any).old_key_version);
            const resolved =
              typeof this.keyResolver === "function"
                ? this.keyResolver(oldVersion)
                : typeof this.keyResolver === "string"
                  ? this.keyResolver
                  : this.keyResolver.get(oldVersion);
            if (resolved) {
              signingKeyHex = resolved;
              signingVersion = oldVersion;
            }
          }

          const timestamp = Date.now();
          const entryHash = computeEntryHash(
            signingKeyHex,
            nextIndex,
            timestamp,
            row.event_type,
            row.entity_id,
            row.assessment_id,
            payload,
            prevHash,
            row.event_id,
            signingVersion,
          );

          const record: AuditRecord = {
            index: nextIndex,
            timestamp,
            action: row.event_type,
            event_id: row.event_id,
            lead_id: row.entity_id,
            assessment_id: row.assessment_id,
            payload,
            prev_hash: prevHash,
            key_version: signingVersion,
            entry_hash: entryHash,
          };

          // Step 5: Append the record
          appendFileSync(this.journalPath, JSON.stringify(record) + "\n", "utf8");

          // Step 6: fsync the journal
          this.syncFile();

          // Step 7: Update the SQLite outbox
          updateStmt.run(row.outbox_id);

          count++;
        } finally {
          // Step 8: Release the lock
          lockHandle.release();
        }
      }

      return ok(count);
    } catch (cause) {
      return err(cause instanceof Error ? cause : new Error(String(cause)));
    }
  }

  private syncFile(): void {
    try {
      const fd = openSync(this.journalPath, "r");
      fsyncSync(fd);
      closeSync(fd);
    } catch {
      // Best effort fsync across OS file handles
    }
  }
}
