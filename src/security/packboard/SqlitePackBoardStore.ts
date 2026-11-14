import { DatabaseSync } from "node:sqlite";
import { dirname } from "node:path";
import { mkdirSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { ok, err, type Result } from "../../domain/result.js";
import type { AssessmentId } from "../../domain/security/assessment.js";
import type {
  Lead,
  LeadClaim,
  LeadFilter,
  LeadId,
  LeadStatus,
  LeadVote,
  PackBoardStore,
} from "../../domain/security/packboard/types.js";
import type {
  PackBoardCasConflictError,
  PackBoardStoreError,
} from "../../domain/security/packboard/errors.js";
import {
  PACKBOARD_DDL,
  type SqliteLeadRow,
} from "./SqlitePackBoardSchema.js";
import { KeyringManager } from "./secureKeyring.js";
import { OutboxFlusher } from "./outboxFlusher.js";
import type { SqliteBlackboardStorage } from "../blackboard/SqliteBlackboardStorage.js";

export interface SqlitePackBoardOptions {
  readonly dbPath?: string | undefined; // Default: ':memory:'
  readonly journalPath?: string | undefined;
  readonly hmacSecret?: string | undefined;
  readonly keyringManager?: KeyringManager | undefined;
  readonly assessmentId?: string | undefined;
  readonly maxBusyRetries?: number | undefined;
  readonly storage?: SqliteBlackboardStorage | undefined;
}

export class SqlitePackBoardStore implements PackBoardStore {
  private readonly db: DatabaseSync;
  private readonly journalPath?: string | undefined;
  private readonly keyringManager: KeyringManager;
  private readonly flusher?: OutboxFlusher | undefined;
  private readonly maxBusyRetries: number;
  private readonly storage?: SqliteBlackboardStorage | undefined;

  constructor(options?: SqlitePackBoardOptions) {
    if (options?.storage) {
      this.storage = options.storage;
      this.db = options.storage.getDatabase();
      this.journalPath = options.journalPath;
      this.maxBusyRetries = options.maxBusyRetries ?? 5;
      this.keyringManager = options.storage.getKeyringManager();
      this.flusher = options.storage.getOutboxFlusher();
      this.initialize();
      return;
    }

    const dbPath = options?.dbPath ?? ":memory:";
    if (dbPath !== ":memory:") {
      mkdirSync(dirname(dbPath), { recursive: true });
    }

    this.db = new DatabaseSync(dbPath);
    this.journalPath = options?.journalPath;
    this.maxBusyRetries = options?.maxBusyRetries ?? 5;

    const defaultAssessmentId = options?.assessmentId ?? "default-assessment";
    if (options?.keyringManager) {
      this.keyringManager = options.keyringManager;
    } else if (options?.hmacSecret) {
      this.keyringManager = KeyringManager.createEphemeral(defaultAssessmentId, options.hmacSecret);
    } else if (dbPath !== ":memory:") {
      const keyringDir = dirname(dbPath);
      const resolveRes = KeyringManager.resolveKeyring(keyringDir, defaultAssessmentId);
      if (!resolveRes.ok) {
        throw resolveRes.error;
      }
      this.keyringManager = resolveRes.value;
    } else {
      this.keyringManager = KeyringManager.createEphemeral(defaultAssessmentId);
    }

    if (this.journalPath) {
      this.flusher = new OutboxFlusher(
        this.db,
        this.journalPath,
        this.keyringManager.getKeyResolver(),
        () => this.keyringManager.getActiveKey(),
      );
    }

    this.initialize();
  }

  private initialize(): void {
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA synchronous = NORMAL;");

    if (!this.storage) {
      const master = this.db
        .prepare("SELECT type FROM sqlite_master WHERE name = 'leads'")
        .get() as { type: string } | undefined;
      if (!master || master.type === "table") {
        this.db.exec(PACKBOARD_DDL);
      }
    }

    if (this.flusher) {
      const reconcileRes = this.flusher.reconcileOnStartup();
      if (!reconcileRes.ok) {
        throw reconcileRes.error;
      }
    }
  }

  public close(): void {
    if (this.storage) {
      // Owned by shared SqliteBlackboardStorage; do not close connection directly
      return;
    }
    try {
      this.db.close();
    } catch {
      // Ignore if already closed
    }
  }

  public getKeyringManager(): KeyringManager {
    return this.keyringManager;
  }

  /**
   * Executes a database operation with exponential backoff on SQLITE_BUSY or SQLITE_LOCKED.
   */
  private withBusyRetry<T>(operation: () => T): T {
    let delay = 50;
    for (let attempt = 0; attempt < this.maxBusyRetries; attempt++) {
      try {
        return operation();
      } catch (error: any) {
        const msg = String(error?.message ?? "");
        const isBusy =
          msg.includes("busy") ||
          msg.includes("locked") ||
          error?.code === "SQLITE_BUSY" ||
          error?.code === "SQLITE_LOCKED";

        if (isBusy && attempt < this.maxBusyRetries - 1) {
          const jitter = Math.floor(Math.random() * 20);
          const sleepMs = delay + jitter;
          const start = Date.now();
          while (Date.now() - start < sleepMs) {
            // spin wait
          }
          delay = Math.min(delay * 1.5, 500);
          continue;
        }
        throw error;
      }
    }
    throw new Error(`Exceeded maximum busy retries (${this.maxBusyRetries})`);
  }

  private rowToLead(row: SqliteLeadRow): Lead {
    return {
      id: row.id as LeadId,
      assessment_id: row.assessment_id as AssessmentId,
      fingerprint: row.fingerprint,
      title: row.title,
      description: row.description,
      asset_id: row.asset_id as any,
      location: JSON.parse(row.location_json),
      classification: JSON.parse(row.classification_json),
      severity: row.severity as any,
      confidence: row.confidence as any,
      status: row.status as LeadStatus,
      smoke_score: Number(row.smoke_score),
      cas_version: Number(row.cas_version),
      provenance: row.provenance as any,
      claim: row.claim_json ? (JSON.parse(row.claim_json) as LeadClaim) : null,
      votes: JSON.parse(row.votes_json) as readonly LeadVote[],
      evidence_hashes: JSON.parse(row.evidence_hashes_json) as readonly string[],
      created_at: Number(row.created_at),
      updated_at: Number(row.updated_at),
    };
  }

  private queueOutbox(
    eventType: string,
    entityId: string,
    assessmentId: string,
    payload: unknown,
  ): void {
    const eventId = randomUUID();
    const now = Date.now();
    const insertStmt = this.db.prepare(`
      INSERT INTO transactional_outbox (
        event_id, event_type, entity_type, entity_id, assessment_id, payload_json, created_at, flushed
      ) VALUES (?, ?, 'lead', ?, ?, ?, ?, 0)
    `);
    insertStmt.run(eventId, eventType, entityId, assessmentId, JSON.stringify(payload), now);
  }

  public async rotateHmacKey(
    rotationEventId: string,
  ): Promise<Result<{ oldVersion: number; newVersion: number; newKeyHex: string }, Error>> {
    const rotateRes = this.keyringManager.rotateKey(rotationEventId);
    if (!rotateRes.ok) {
      return err(rotateRes.error);
    }

    this.withBusyRetry(() => {
      this.db.exec("BEGIN IMMEDIATE;");
      try {
        this.queueOutbox(
          "KEY_ROTATION",
          "keyring",
          this.keyringManager.getAssessmentId(),
          {
            old_key_version: rotateRes.value.old_version,
            new_key_version: rotateRes.value.new_version,
            rotation_event_id: rotationEventId,
            proof_new_key: rotateRes.value.proof_new_key,
          },
        );
        this.db.exec("COMMIT;");
      } catch (e) {
        this.db.exec("ROLLBACK;");
        throw e;
      }
    });

    if (this.flusher) {
      this.flusher.drainOutbox();
    }

    return ok({
      oldVersion: rotateRes.value.old_version,
      newVersion: rotateRes.value.new_version,
      newKeyHex: rotateRes.value.new_key_hex,
    });
  }

  public async postLead(lead: Lead): Promise<Result<Lead, PackBoardStoreError>> {
    return this.withBusyRetry(() => {
      this.db.exec("BEGIN IMMEDIATE;");
      try {
        const findStmt = this.db.prepare(
          "SELECT * FROM leads WHERE assessment_id = ? AND fingerprint = ?",
        );
        const existingRow = findStmt.get(lead.assessment_id, lead.fingerprint) as unknown as
          | SqliteLeadRow
          | undefined;

        if (existingRow) {
          const existing = this.rowToLead(existingRow);
          const newSmoke = existing.smoke_score + 1;
          const mergedEvidence = Array.from(
            new Set([...existing.evidence_hashes, ...lead.evidence_hashes]),
          );
          const now = Date.now();

          const updateStmt = this.db.prepare(
            `UPDATE leads 
             SET smoke_score = ?, evidence_hashes_json = ?, updated_at = ? 
             WHERE id = ? AND assessment_id = ?`,
          );
          updateStmt.run(
            newSmoke,
            JSON.stringify(mergedEvidence),
            now,
            existing.id,
            existing.assessment_id,
          );

          const updated: Lead = {
            ...existing,
            smoke_score: newSmoke,
            evidence_hashes: mergedEvidence,
            updated_at: now,
          };

          this.queueOutbox("CORROBORATE_LEAD", updated.id, updated.assessment_id, {
            cas_version: updated.cas_version,
            status: updated.status,
            smoke_score: updated.smoke_score,
          });

          this.db.exec("COMMIT;");
          if (this.flusher) this.flusher.drainOutbox();
          return ok(updated);
        }

        const insertStmt = this.db.prepare(`
          INSERT INTO leads (
            id, assessment_id, fingerprint, title, description, asset_id,
            location_json, classification_json, severity, confidence, status,
            smoke_score, cas_version, provenance, claim_json, votes_json,
            evidence_hashes_json, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        insertStmt.run(
          lead.id,
          lead.assessment_id,
          lead.fingerprint,
          lead.title,
          lead.description,
          lead.asset_id,
          JSON.stringify(lead.location),
          JSON.stringify(lead.classification),
          lead.severity,
          lead.confidence,
          lead.status,
          lead.smoke_score,
          lead.cas_version,
          lead.provenance,
          lead.claim ? JSON.stringify(lead.claim) : null,
          JSON.stringify(lead.votes),
          JSON.stringify(lead.evidence_hashes),
          lead.created_at,
          lead.updated_at,
        );

        this.queueOutbox("POST_LEAD", lead.id, lead.assessment_id, {
          cas_version: lead.cas_version,
          status: lead.status,
          smoke_score: lead.smoke_score,
        });

        this.db.exec("COMMIT;");
        if (this.flusher) this.flusher.drainOutbox();
        return ok(lead);
      } catch (cause) {
        this.db.exec("ROLLBACK;");
        return err({
          code: "STORE_ERROR",
          message: `Failed to post lead: ${String(cause)}`,
          cause,
        });
      }
    });
  }

  public async getLead(
    assessmentId: AssessmentId,
    leadId: LeadId,
  ): Promise<Result<Lead | null, PackBoardStoreError>> {
    return this.withBusyRetry(() => {
      try {
        const stmt = this.db.prepare(
          "SELECT * FROM leads WHERE assessment_id = ? AND id = ?",
        );
        const row = stmt.get(assessmentId, leadId) as unknown as SqliteLeadRow | undefined;
        if (!row) {
          return ok(null);
        }
        return ok(this.rowToLead(row));
      } catch (cause) {
        return err({
          code: "STORE_ERROR",
          message: `Failed to get lead: ${String(cause)}`,
          cause,
        });
      }
    });
  }

  public async claimLead(
    assessmentId: AssessmentId,
    leadId: LeadId,
    claim: LeadClaim,
    expectedVersion: number,
  ): Promise<Result<Lead, PackBoardCasConflictError | PackBoardStoreError>> {
    return this.withBusyRetry(() => {
      this.db.exec("BEGIN IMMEDIATE;");
      try {
        const now = Date.now();
        const updateStmt = this.db.prepare(`
          UPDATE leads 
          SET status = 'claimed', 
              claim_json = ?, 
              cas_version = cas_version + 1, 
              updated_at = ?
          WHERE id = ? AND assessment_id = ? AND cas_version = ?
        `);

        const result = updateStmt.run(
          JSON.stringify(claim),
          now,
          leadId,
          assessmentId,
          expectedVersion,
        );

        if (Number(result.changes) === 0) {
          this.db.exec("ROLLBACK;");
          const currentLeadRes = this.db.prepare(
            "SELECT * FROM leads WHERE assessment_id = ? AND id = ?",
          ).get(assessmentId, leadId) as unknown as SqliteLeadRow | undefined;

          if (!currentLeadRes) {
            return err({
              code: "STORE_ERROR",
              message: `Lead ${leadId} not found during claim`,
            });
          }

          const current = this.rowToLead(currentLeadRes);
          return err({
            code: "CAS_CONFLICT",
            lead_id: leadId,
            expected_version: expectedVersion,
            current_lead: current,
            message: `Lead ${leadId} CAS version mismatch (expected ${expectedVersion}, got ${current.cas_version})`,
          });
        }

        const updatedRow = this.db.prepare(
          "SELECT * FROM leads WHERE assessment_id = ? AND id = ?",
        ).get(assessmentId, leadId) as unknown as SqliteLeadRow;
        const updatedLead = this.rowToLead(updatedRow);

        this.queueOutbox("CLAIM_LEAD", updatedLead.id, updatedLead.assessment_id, {
          cas_version: updatedLead.cas_version,
          status: updatedLead.status,
          claim: updatedLead.claim,
        });

        this.db.exec("COMMIT;");
        if (this.flusher) this.flusher.drainOutbox();
        return ok(updatedLead);
      } catch (cause) {
        this.db.exec("ROLLBACK;");
        return err({
          code: "STORE_ERROR",
          message: `Failed to claim lead: ${String(cause)}`,
          cause,
        });
      }
    });
  }

  public async extendLease(
    assessmentId: AssessmentId,
    leadId: LeadId,
    claimant: LeadClaim,
    additionalSeconds: number,
  ): Promise<Result<Lead, PackBoardStoreError>> {
    return this.withBusyRetry(() => {
      this.db.exec("BEGIN IMMEDIATE;");
      try {
        const getRes = this.db.prepare(
          "SELECT * FROM leads WHERE assessment_id = ? AND id = ?",
        ).get(assessmentId, leadId) as unknown as SqliteLeadRow | undefined;

        if (!getRes) {
          this.db.exec("ROLLBACK;");
          return err({
            code: "STORE_ERROR",
            message: `Lead ${leadId} not found to extend lease`,
          });
        }

        const current = this.rowToLead(getRes);
        if (!current.claim || current.claim.agent_id !== claimant.agent_id) {
          this.db.exec("ROLLBACK;");
          return err({
            code: "STORE_ERROR",
            message: `Agent ${claimant.agent_id} does not hold active claim on lead ${leadId}`,
          });
        }

        const newLeaseUntil = Math.max(current.claim.lease_until, Date.now()) + additionalSeconds * 1000;
        const updatedClaim: LeadClaim = {
          ...current.claim,
          lease_until: newLeaseUntil,
        };

        const now = Date.now();
        const updateStmt = this.db.prepare(`
          UPDATE leads 
          SET claim_json = ?, updated_at = ?
          WHERE id = ? AND assessment_id = ?
        `);
        updateStmt.run(JSON.stringify(updatedClaim), now, leadId, assessmentId);

        const updated: Lead = {
          ...current,
          claim: updatedClaim,
          updated_at: now,
        };

        this.queueOutbox("EXTEND_LEASE", updated.id, updated.assessment_id, {
          cas_version: updated.cas_version,
          lease_until: newLeaseUntil,
        });

        this.db.exec("COMMIT;");
        if (this.flusher) this.flusher.drainOutbox();
        return ok(updated);
      } catch (cause) {
        this.db.exec("ROLLBACK;");
        return err({
          code: "STORE_ERROR",
          message: `Failed to extend lease: ${String(cause)}`,
          cause,
        });
      }
    });
  }

  public async releaseClaim(
    assessmentId: AssessmentId,
    leadId: LeadId,
    agentId: string,
    finalStatus?: LeadStatus,
  ): Promise<Result<Lead, PackBoardStoreError>> {
    return this.withBusyRetry(() => {
      this.db.exec("BEGIN IMMEDIATE;");
      try {
        const getRes = this.db.prepare(
          "SELECT * FROM leads WHERE assessment_id = ? AND id = ?",
        ).get(assessmentId, leadId) as unknown as SqliteLeadRow | undefined;

        if (!getRes) {
          this.db.exec("ROLLBACK;");
          return err({
            code: "STORE_ERROR",
            message: `Lead ${leadId} not found to release claim`,
          });
        }

        const current = this.rowToLead(getRes);
        if (current.claim && current.claim.agent_id !== agentId) {
          this.db.exec("ROLLBACK;");
          return err({
            code: "STORE_ERROR",
            message: `Agent ${agentId} does not hold claim on lead ${leadId} (held by ${current.claim.agent_id})`,
          });
        }

        const targetStatus = finalStatus ?? (current.status === "claimed" ? "open" : current.status);
        const now = Date.now();
        const updateStmt = this.db.prepare(`
          UPDATE leads 
          SET status = ?, claim_json = NULL, cas_version = cas_version + 1, updated_at = ?
          WHERE id = ? AND assessment_id = ?
        `);
        updateStmt.run(targetStatus, now, leadId, assessmentId);

        const updated: Lead = {
          ...current,
          status: targetStatus,
          claim: null,
          cas_version: current.cas_version + 1,
          updated_at: now,
        };

        this.queueOutbox("RELEASE_CLAIM", updated.id, updated.assessment_id, {
          cas_version: updated.cas_version,
          status: targetStatus,
        });

        this.db.exec("COMMIT;");
        if (this.flusher) this.flusher.drainOutbox();
        return ok(updated);
      } catch (cause) {
        this.db.exec("ROLLBACK;");
        return err({
          code: "STORE_ERROR",
          message: `Failed to release claim: ${String(cause)}`,
          cause,
        });
      }
    });
  }

  public async voteLead(
    assessmentId: AssessmentId,
    leadId: LeadId,
    vote: LeadVote,
    expectedVersion: number,
  ): Promise<Result<Lead, PackBoardCasConflictError | PackBoardStoreError>> {
    return this.withBusyRetry(() => {
      this.db.exec("BEGIN IMMEDIATE;");
      try {
        const getRes = this.db.prepare(
          "SELECT * FROM leads WHERE assessment_id = ? AND id = ?",
        ).get(assessmentId, leadId) as unknown as SqliteLeadRow | undefined;

        if (!getRes) {
          this.db.exec("ROLLBACK;");
          return err({
            code: "STORE_ERROR",
            message: `Lead ${leadId} not found to cast vote`,
          });
        }

        const current = this.rowToLead(getRes);
        if (current.cas_version !== expectedVersion) {
          this.db.exec("ROLLBACK;");
          return err({
            code: "CAS_CONFLICT",
            lead_id: leadId,
            expected_version: expectedVersion,
            current_lead: current,
            message: `Lead ${leadId} version conflict during vote (expected ${expectedVersion}, got ${current.cas_version})`,
          });
        }

        const newVotes = [...current.votes, vote];
        const newEvidence = Array.from(
          new Set([...current.evidence_hashes, ...vote.evidence_hashes]),
        );
        const now = Date.now();

        const updateStmt = this.db.prepare(`
          UPDATE leads 
          SET votes_json = ?, evidence_hashes_json = ?, cas_version = cas_version + 1, updated_at = ?
          WHERE id = ? AND assessment_id = ? AND cas_version = ?
        `);
        const result = updateStmt.run(
          JSON.stringify(newVotes),
          JSON.stringify(newEvidence),
          now,
          leadId,
          assessmentId,
          expectedVersion,
        );

        if (Number(result.changes) === 0) {
          this.db.exec("ROLLBACK;");
          const fresh = this.rowToLead(
            this.db.prepare("SELECT * FROM leads WHERE assessment_id = ? AND id = ?").get(
              assessmentId,
              leadId,
            ) as unknown as SqliteLeadRow,
          );
          return err({
            code: "CAS_CONFLICT",
            lead_id: leadId,
            expected_version: expectedVersion,
            current_lead: fresh,
            message: `Concurrent update during vote on lead ${leadId}`,
          });
        }

        const updated: Lead = {
          ...current,
          votes: newVotes,
          evidence_hashes: newEvidence,
          cas_version: current.cas_version + 1,
          updated_at: now,
        };

        this.queueOutbox("VOTE_LEAD", updated.id, updated.assessment_id, {
          cas_version: updated.cas_version,
          votes_count: updated.votes.length,
        });

        this.db.exec("COMMIT;");
        if (this.flusher) this.flusher.drainOutbox();
        return ok(updated);
      } catch (cause) {
        this.db.exec("ROLLBACK;");
        return err({
          code: "STORE_ERROR",
          message: `Failed to vote on lead: ${String(cause)}`,
          cause,
        });
      }
    });
  }

  public async listLeads(
    assessmentId: AssessmentId,
    filter?: LeadFilter,
  ): Promise<Result<readonly Lead[], PackBoardStoreError>> {
    return this.withBusyRetry(() => {
      try {
        let query = "SELECT * FROM leads WHERE assessment_id = ?";
        const params: any[] = [assessmentId];

        if (filter?.status) {
          if (Array.isArray(filter.status)) {
            query += ` AND status IN (${filter.status.map(() => "?").join(",")})`;
            params.push(...filter.status);
          } else {
            query += " AND status = ?";
            params.push(filter.status);
          }
        }

        if (filter?.asset_id) {
          query += " AND asset_id = ?";
          params.push(filter.asset_id);
        }

        if (filter?.unclaimed_only) {
          query += " AND (status = 'open' OR claim_json IS NULL)";
        }

        query += " ORDER BY smoke_score DESC, updated_at DESC";

        const stmt = this.db.prepare(query);
        const rows = stmt.all(...params) as unknown as SqliteLeadRow[];
        const leads = rows.map((r) => this.rowToLead(r));
        return ok(leads);
      } catch (cause) {
        return err({
          code: "STORE_ERROR",
          message: `Failed to list leads: ${String(cause)}`,
          cause,
        });
      }
    });
  }

  public async reapExpiredLeases(
    assessmentId: AssessmentId,
    now: number = Date.now(),
  ): Promise<Result<number, PackBoardStoreError>> {
    return this.withBusyRetry(() => {
      this.db.exec("BEGIN IMMEDIATE;");
      try {
        const stmt = this.db.prepare(
          "SELECT * FROM leads WHERE assessment_id = ? AND status = 'claimed' AND claim_json IS NOT NULL",
        );
        const rows = stmt.all(assessmentId) as unknown as SqliteLeadRow[];
        let reapedCount = 0;

        for (const row of rows) {
          const lead = this.rowToLead(row);
          if (lead.claim && lead.claim.lease_until < now) {
            const updateStmt = this.db.prepare(`
              UPDATE leads 
              SET status = 'open', claim_json = NULL, cas_version = cas_version + 1, updated_at = ?
              WHERE id = ? AND assessment_id = ?
            `);
            updateStmt.run(now, lead.id, assessmentId);
            reapedCount++;

            this.queueOutbox("REAP_LEASE", lead.id, lead.assessment_id, {
              status: "open",
              cas_version: lead.cas_version + 1,
            });
          }
        }

        this.db.exec("COMMIT;");
        if (this.flusher) this.flusher.drainOutbox();
        return ok(reapedCount);
      } catch (cause) {
        this.db.exec("ROLLBACK;");
        return err({
          code: "STORE_ERROR",
          message: `Failed to reap expired leases: ${String(cause)}`,
          cause,
        });
      }
    });
  }
}
