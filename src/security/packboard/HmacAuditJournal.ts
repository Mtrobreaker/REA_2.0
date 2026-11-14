import { createHmac } from "node:crypto";
import { appendFileSync, existsSync, readFileSync, truncateSync, statSync, openSync, closeSync } from "node:fs";
import { ok, err, type Result } from "../../domain/result.js";
import { acquireJournalLockSync } from "./JournalLock.js";

export interface AuditRecord {
  readonly index: number;
  readonly timestamp: number;
  readonly action: string;
  readonly event_id?: string | undefined;
  readonly lead_id: string;
  readonly assessment_id: string;
  readonly payload: unknown;
  readonly prev_hash: string;
  readonly key_version?: number | undefined;
  readonly entry_hash: string;
}

export interface KeyRotationPayload {
  readonly old_key_version: number;
  readonly new_key_version: number;
  readonly rotation_event_id: string;
  readonly proof_new_key: string;
}

export const GENESIS_HASH = "0".repeat(64);

/**
 * Computes the HMAC-SHA256 entry hash chaining to the previous record hash.
 * Supports both versioned records and legacy test records.
 */
export function computeEntryHash(
  secret: string,
  index: number,
  timestamp: number,
  action: string,
  leadId: string,
  assessmentId: string,
  payload: unknown,
  prevHash: string,
  eventId?: string | undefined,
  keyVersion?: number | undefined,
): string {
  const payloadStr = JSON.stringify(payload);
  const data =
    eventId !== undefined || keyVersion !== undefined
      ? [
          prevHash,
          index.toString(),
          timestamp.toString(),
          action,
          eventId ?? "",
          leadId,
          assessmentId,
          (keyVersion ?? 1).toString(),
          payloadStr,
        ].join("::")
      : [
          prevHash,
          index.toString(),
          timestamp.toString(),
          action,
          leadId,
          assessmentId,
          payloadStr,
        ].join("::");

  return createHmac("sha256", secret).update(data, "utf8").digest("hex");
}

export interface AppendAuditOptions {
  readonly lastKnownHash?: string | undefined;
  readonly lastKnownIndex?: number | undefined;
  readonly eventId?: string | undefined;
  readonly keyVersion?: number | undefined;
}

/**
 * Appends a tamper-evident audit record to a JSONL log file under exclusive cross-process lock.
 */
export function appendAuditRecord(
  journalPath: string,
  secret: string,
  action: string,
  leadId: string,
  assessmentId: string,
  payload: unknown,
  optionsOrLastHash?: string | AppendAuditOptions | undefined,
  lastKnownIndex?: number | undefined,
): Result<AuditRecord, Error> {
  const lock = acquireJournalLockSync(journalPath);
  try {
    let prevHash: string;
    let nextIndex: number;
    let eventId: string | undefined;
    let keyVersion: number | undefined;

    if (typeof optionsOrLastHash === "object" && optionsOrLastHash !== null) {
      prevHash = optionsOrLastHash.lastKnownHash ?? GENESIS_HASH;
      nextIndex = (optionsOrLastHash.lastKnownIndex ?? -1) + 1;
      eventId = optionsOrLastHash.eventId;
      keyVersion = optionsOrLastHash.keyVersion;
    } else {
      prevHash = (typeof optionsOrLastHash === "string" ? optionsOrLastHash : undefined) ?? GENESIS_HASH;
      nextIndex = (lastKnownIndex ?? -1) + 1;
    }

    if (
      (typeof optionsOrLastHash !== "object" || optionsOrLastHash.lastKnownHash === undefined) &&
      existsSync(journalPath)
    ) {
      const content = readFileSync(journalPath, "utf8").trim();
      if (content.length > 0) {
        const lines = content.split("\n");
        const lastLine = lines[lines.length - 1];
        if (lastLine) {
          const parsed = JSON.parse(lastLine) as AuditRecord;
          prevHash = parsed.entry_hash;
          nextIndex = parsed.index + 1;
        }
      }
    }

    const timestamp = Date.now();
    const entryHash = computeEntryHash(
      secret,
      nextIndex,
      timestamp,
      action,
      leadId,
      assessmentId,
      payload,
      prevHash,
      eventId,
      keyVersion,
    );

    const record: AuditRecord = {
      index: nextIndex,
      timestamp,
      action,
      ...(eventId ? { event_id: eventId } : {}),
      lead_id: leadId,
      assessment_id: assessmentId,
      payload,
      prev_hash: prevHash,
      ...(keyVersion ? { key_version: keyVersion } : {}),
      entry_hash: entryHash,
    };

    appendFileSync(journalPath, JSON.stringify(record) + "\n", "utf8");
    return ok(record);
  } catch (cause) {
    return err(cause instanceof Error ? cause : new Error(String(cause)));
  } finally {
    lock.release();
  }
}

/**
 * Truncates an incomplete trailing record at the end of a journal file if a crash
 * interrupted a write before newline flush. Never truncates complete records.
 */
export function truncateIncompleteTrailingLine(
  journalPath: string,
): Result<{ truncated: boolean; bytesRemoved: number }, Error> {
  try {
    if (!existsSync(journalPath)) {
      return ok({ truncated: false, bytesRemoved: 0 });
    }

    const stat = statSync(journalPath);
    if (stat.size === 0) {
      return ok({ truncated: false, bytesRemoved: 0 });
    }

    const raw = readFileSync(journalPath);
    // If file ends with '\n', verify if the last line is parseable JSON
    if (raw[raw.length - 1] === 0x0a) {
      const text = raw.toString("utf8").trim();
      const lastLine = text.substring(text.lastIndexOf("\n") + 1);
      try {
        JSON.parse(lastLine);
        return ok({ truncated: false, bytesRemoved: 0 });
      } catch {
        // Last line before newline is corrupted JSON
      }
    }

    // Incomplete line: find last occurrence of '\n'
    let lastNewline = -1;
    for (let i = raw.length - 2; i >= 0; i--) {
      if (raw[i] === 0x0a) {
        lastNewline = i;
        break;
      }
    }

    const truncateTo = lastNewline === -1 ? 0 : lastNewline + 1;
    const bytesRemoved = raw.length - truncateTo;
    truncateSync(journalPath, truncateTo);

    return ok({ truncated: true, bytesRemoved });
  } catch (cause) {
    return err(cause instanceof Error ? cause : new Error(String(cause)));
  }
}

export type KeyResolver = string | ((version: number) => string | undefined) | Map<number, string>;

function resolveKey(resolver: KeyResolver, version: number): string | undefined {
  if (typeof resolver === "string") {
    return resolver;
  }
  if (typeof resolver === "function") {
    return resolver(version);
  }
  return resolver.get(version);
}

/**
 * Validates the full cryptographic hash chain of an audit journal file.
 * Supports multi-version key history and authenticated key rotation events.
 * Returns true if valid, or returns error detailing the exact corrupted entry.
 */
export function verifyAuditJournal(
  journalPath: string,
  keyResolver: KeyResolver,
): Result<boolean, { code: "AUDIT_CHAIN_CORRUPTED"; line: number; reason: string }> {
  if (!existsSync(journalPath)) {
    return ok(true);
  }

  const content = readFileSync(journalPath, "utf8").trim();
  if (content.length === 0) {
    return ok(true);
  }

  const lines = content.split("\n");
  let expectedPrevHash = GENESIS_HASH;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;

    let record: AuditRecord;
    try {
      record = JSON.parse(line) as AuditRecord;
    } catch {
      return err({
        code: "AUDIT_CHAIN_CORRUPTED",
        line: i + 1,
        reason: "Malformed JSON line",
      });
    }

    if (record.index !== i) {
      return err({
        code: "AUDIT_CHAIN_CORRUPTED",
        line: i + 1,
        reason: `Index mismatch (expected ${i}, got ${record.index})`,
      });
    }

    if (record.prev_hash !== expectedPrevHash) {
      return err({
        code: "AUDIT_CHAIN_CORRUPTED",
        line: i + 1,
        reason: `Broken chain link (expected prev_hash ${expectedPrevHash}, got ${record.prev_hash})`,
      });
    }

    const keyVersion = record.key_version ?? 1;
    const secret = resolveKey(keyResolver, keyVersion);

    if (!secret) {
      return err({
        code: "AUDIT_CHAIN_CORRUPTED",
        line: i + 1,
        reason: `Missing key for version ${keyVersion} at entry ${i}`,
      });
    }

    const recalculated = computeEntryHash(
      secret,
      record.index,
      record.timestamp,
      record.action,
      record.lead_id,
      record.assessment_id,
      record.payload,
      record.prev_hash,
      record.event_id,
      record.key_version,
    );

    if (recalculated !== record.entry_hash) {
      return err({
        code: "AUDIT_CHAIN_CORRUPTED",
        line: i + 1,
        reason: `HMAC signature mismatch at entry ${i}`,
      });
    }

    // Verify key rotation authentication if this is a rotation event
    if (record.action === "KEY_ROTATION") {
      const payload = record.payload as Partial<KeyRotationPayload> | undefined;
      if (
        !payload ||
        payload.new_key_version === undefined ||
        !payload.proof_new_key ||
        !payload.rotation_event_id
      ) {
        return err({
          code: "AUDIT_CHAIN_CORRUPTED",
          line: i + 1,
          reason: `Invalid KEY_ROTATION payload at entry ${i}`,
        });
      }

      const nextSecret = resolveKey(keyResolver, payload.new_key_version);
      if (!nextSecret) {
        return err({
          code: "AUDIT_CHAIN_CORRUPTED",
          line: i + 1,
          reason: `Missing new key for rotation version ${payload.new_key_version} at entry ${i}`,
        });
      }

      const expectedProof = createHmac("sha256", nextSecret)
        .update(`REA_KEY_ROTATION_CONFIRMATION:${payload.rotation_event_id}:${keyVersion}`, "utf8")
        .digest("hex");

      if (expectedProof !== payload.proof_new_key) {
        return err({
          code: "AUDIT_CHAIN_CORRUPTED",
          line: i + 1,
          reason: `Cryptographic proof for new key failed at KEY_ROTATION entry ${i}`,
        });
      }
    }

    expectedPrevHash = record.entry_hash;
  }

  return ok(true);
}
