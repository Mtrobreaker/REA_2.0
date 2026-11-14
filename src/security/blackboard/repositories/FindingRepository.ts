import { ok, err, type Result } from "../../../domain/result.js";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { AssetId } from "../../../domain/security/asset.js";
import type { FindingId } from "../../../domain/security/finding.js";
import type {
  FindingRecord,
  FindingState,
  FindingFilter,
  IFindingRepository,
} from "../../../domain/security/blackboard/types.js";
import type { BlackboardError } from "../../../domain/security/blackboard/errors.js";
import type { SqliteBlackboardStorage } from "../SqliteBlackboardStorage.js";

interface SqliteFindingRow {
  readonly id: string;
  readonly assessment_id: string;
  readonly fingerprint: string;
  readonly asset_id: string;
  readonly title: string;
  readonly description: string;
  readonly state: string;
  readonly cwe_json: string;
  readonly severity_json: string;
  readonly confidence_json: string;
  readonly location_json: string;
  readonly evidence_ids_json: string;
  readonly remediation_json: string | null;
  readonly cas_version: number;
  readonly created_at: number;
  readonly updated_at: number;
}

export class FindingRepository implements IFindingRepository {
  private readonly storage: SqliteBlackboardStorage;

  constructor(storage: SqliteBlackboardStorage) {
    this.storage = storage;
  }

  private rowToRecord(row: SqliteFindingRow): FindingRecord {
    return {
      id: row.id as FindingId,
      assessment_id: row.assessment_id as AssessmentId,
      fingerprint: row.fingerprint,
      asset_id: row.asset_id as AssetId,
      title: row.title,
      description: row.description,
      state: row.state as FindingState,
      cwe: JSON.parse(row.cwe_json),
      severity: JSON.parse(row.severity_json),
      confidence: JSON.parse(row.confidence_json),
      location: JSON.parse(row.location_json),
      evidence_ids: JSON.parse(row.evidence_ids_json),
      remediation: row.remediation_json ? JSON.parse(row.remediation_json) : null,
      cas_version: row.cas_version,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  public async create(finding: FindingRecord): Promise<Result<FindingRecord, BlackboardError>> {
    try {
      return this.storage.transaction((tx) => {
        const stmt = tx.db.prepare(`
          INSERT INTO findings (
            id, assessment_id, fingerprint, asset_id, title, description, state,
            cwe_json, severity_json, confidence_json, location_json, evidence_ids_json,
            remediation_json, cas_version, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        stmt.run(
          finding.id,
          finding.assessment_id,
          finding.fingerprint,
          finding.asset_id,
          finding.title,
          finding.description,
          finding.state,
          JSON.stringify(finding.cwe),
          JSON.stringify(finding.severity),
          JSON.stringify(finding.confidence),
          JSON.stringify(finding.location),
          JSON.stringify(finding.evidence_ids),
          finding.remediation ? JSON.stringify(finding.remediation) : null,
          finding.cas_version,
          finding.created_at,
          finding.updated_at,
        );

        tx.queueOutbox("FINDING_CREATED", "finding", finding.id, finding.assessment_id, {
          fingerprint: finding.fingerprint,
          title: finding.title,
          state: finding.state,
          asset_id: finding.asset_id,
        });

        return ok(finding);
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "FindingRepository.create",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async getById(
    assessmentId: AssessmentId,
    findingId: FindingId,
  ): Promise<Result<FindingRecord | null, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      const stmt = db.prepare("SELECT * FROM findings WHERE assessment_id = ? AND id = ?");
      const row = stmt.get(assessmentId, findingId) as SqliteFindingRow | undefined;
      if (!row) {
        return ok(null);
      }
      return ok(this.rowToRecord(row));
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "FindingRepository.getById",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async getByFingerprint(
    assessmentId: AssessmentId,
    fingerprint: string,
  ): Promise<Result<FindingRecord | null, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      const stmt = db.prepare("SELECT * FROM findings WHERE assessment_id = ? AND fingerprint = ?");
      const row = stmt.get(assessmentId, fingerprint) as SqliteFindingRow | undefined;
      if (!row) {
        return ok(null);
      }
      return ok(this.rowToRecord(row));
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "FindingRepository.getByFingerprint",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async transitionState(
    assessmentId: AssessmentId,
    findingId: FindingId,
    newState: FindingState,
    expectedVersion: number,
    metadata?: Partial<FindingRecord>,
  ): Promise<Result<FindingRecord, BlackboardError>> {
    try {
      return this.storage.transaction((tx) => {
        const findStmt = tx.db.prepare("SELECT * FROM findings WHERE assessment_id = ? AND id = ?");
        const row = findStmt.get(assessmentId, findingId) as SqliteFindingRow | undefined;
        if (!row) {
          return err({
            code: "FINDING_NOT_FOUND",
            findingId,
            message: `Finding ${findingId} not found in assessment ${assessmentId}`,
          });
        }

        const existing = this.rowToRecord(row);
        if (existing.cas_version !== expectedVersion) {
          return err({
            code: "CAS_CONFLICT",
            entityId: findingId,
            expectedVersion,
            actualVersion: existing.cas_version,
            currentEntity: existing,
            message: `CAS version mismatch on finding ${findingId}: expected ${expectedVersion}, actual ${existing.cas_version}`,
          });
        }

        const now = Date.now();
        const newCasVersion = existing.cas_version + 1;
        const updatedSeverity = metadata?.severity ?? existing.severity;
        const updatedConfidence = metadata?.confidence ?? existing.confidence;
        const updatedEvidence = metadata?.evidence_ids
          ? Array.from(new Set([...existing.evidence_ids, ...metadata.evidence_ids]))
          : existing.evidence_ids;

        const updateStmt = tx.db.prepare(`
          UPDATE findings
          SET state = ?,
              severity_json = ?,
              confidence_json = ?,
              evidence_ids_json = ?,
              cas_version = ?,
              updated_at = ?
          WHERE assessment_id = ? AND id = ? AND cas_version = ?
        `);

        const res = updateStmt.run(
          newState,
          JSON.stringify(updatedSeverity),
          JSON.stringify(updatedConfidence),
          JSON.stringify(updatedEvidence),
          newCasVersion,
          now,
          assessmentId,
          findingId,
          expectedVersion,
        );

        if (res.changes === 0) {
          const fresh = this.rowToRecord(findStmt.get(assessmentId, findingId) as unknown as SqliteFindingRow);
          return err({
            code: "CAS_CONFLICT",
            entityId: findingId,
            expectedVersion,
            actualVersion: fresh.cas_version,
            currentEntity: fresh,
            message: `Concurrent race modifying finding ${findingId}`,
          });
        }

        const updated: FindingRecord = {
          ...existing,
          state: newState,
          severity: updatedSeverity,
          confidence: updatedConfidence,
          evidence_ids: updatedEvidence,
          cas_version: newCasVersion,
          updated_at: now,
        };

        tx.queueOutbox("FINDING_STATE_TRANSITIONED", "finding", findingId, assessmentId, {
          previous_state: existing.state,
          new_state: newState,
          cas_version: newCasVersion,
        });

        return ok(updated);
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "FindingRepository.transitionState",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async listByAssessment(
    assessmentId: AssessmentId,
    filter?: FindingFilter,
  ): Promise<Result<ReadonlyArray<FindingRecord>, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      let sql = "SELECT * FROM findings WHERE assessment_id = ?";
      const params: any[] = [assessmentId];

      if (filter?.state) {
        sql += " AND state = ?";
        params.push(filter.state);
      }
      if (filter?.asset_id) {
        sql += " AND asset_id = ?";
        params.push(filter.asset_id);
      }
      sql += " ORDER BY created_at ASC";

      const stmt = db.prepare(sql);
      const rows = stmt.all(...params) as unknown as ReadonlyArray<SqliteFindingRow>;
      return ok(rows.map((r) => this.rowToRecord(r)));
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "FindingRepository.listByAssessment",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }
}
