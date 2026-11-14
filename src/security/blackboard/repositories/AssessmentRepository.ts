import { ok, err, type Result } from "../../../domain/result.js";
import type { AssessmentId, AssessmentMetrics } from "../../../domain/security/assessment.js";
import type {
  AssessmentRecord,
  AssessmentStatus,
  IAssessmentRepository,
} from "../../../domain/security/blackboard/types.js";
import type { BlackboardError } from "../../../domain/security/blackboard/errors.js";
import type { SqliteBlackboardStorage } from "../SqliteBlackboardStorage.js";

interface SqliteAssessmentRow {
  readonly id: string;
  readonly name: string;
  readonly status: string;
  readonly objective_json: string;
  readonly authorization_json: string;
  readonly metrics_json: string;
  readonly created_at: number;
  readonly updated_at: number;
}

export class AssessmentRepository implements IAssessmentRepository {
  private readonly storage: SqliteBlackboardStorage;

  constructor(storage: SqliteBlackboardStorage) {
    this.storage = storage;
  }

  private rowToRecord(row: SqliteAssessmentRow): AssessmentRecord {
    return {
      id: row.id as AssessmentId,
      name: row.name,
      status: row.status as AssessmentStatus,
      objective: JSON.parse(row.objective_json),
      authorization: JSON.parse(row.authorization_json),
      metrics: JSON.parse(row.metrics_json),
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  public async create(
    assessment: AssessmentRecord,
  ): Promise<Result<AssessmentRecord, BlackboardError>> {
    try {
      return this.storage.transaction((tx) => {
        const stmt = tx.db.prepare(`
          INSERT INTO assessments (
            id, name, status, objective_json, authorization_json, metrics_json, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(
          assessment.id,
          assessment.name,
          assessment.status,
          JSON.stringify(assessment.objective),
          JSON.stringify(assessment.authorization),
          JSON.stringify(assessment.metrics),
          assessment.created_at,
          assessment.updated_at,
        );

        tx.queueOutbox("ASSESSMENT_CREATED", "assessment", assessment.id, assessment.id, {
          name: assessment.name,
          status: assessment.status,
          objective: assessment.objective,
        });

        return ok(assessment);
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "AssessmentRepository.create",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async findById(
    id: AssessmentId,
  ): Promise<Result<AssessmentRecord | null, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      const stmt = db.prepare("SELECT * FROM assessments WHERE id = ?");
      const row = stmt.get(id) as SqliteAssessmentRow | undefined;
      if (!row) {
        return ok(null);
      }
      return ok(this.rowToRecord(row));
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "AssessmentRepository.findById",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async updateStatus(
    id: AssessmentId,
    status: AssessmentStatus,
    metrics?: Partial<AssessmentMetrics>,
  ): Promise<Result<AssessmentRecord, BlackboardError>> {
    try {
      return this.storage.transaction((tx) => {
        const selectStmt = tx.db.prepare("SELECT * FROM assessments WHERE id = ?");
        const existingRow = selectStmt.get(id) as SqliteAssessmentRow | undefined;
        if (!existingRow) {
          return err({
            code: "ASSESSMENT_NOT_FOUND",
            assessmentId: id,
            message: `Assessment ${id} not found`,
          });
        }

        const existing = this.rowToRecord(existingRow);
        const updatedMetrics = metrics ? { ...existing.metrics, ...metrics } : existing.metrics;
        const now = Date.now();

        const updateStmt = tx.db.prepare(`
          UPDATE assessments
          SET status = ?, metrics_json = ?, updated_at = ?
          WHERE id = ?
        `);
        updateStmt.run(status, JSON.stringify(updatedMetrics), now, id);

        tx.queueOutbox("ASSESSMENT_STATUS_UPDATED", "assessment", id, id, {
          previous_status: existing.status,
          new_status: status,
          metrics: updatedMetrics,
        });

        const updated: AssessmentRecord = {
          ...existing,
          status,
          metrics: updatedMetrics,
          updated_at: now,
        };

        return ok(updated);
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "AssessmentRepository.updateStatus",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async list(): Promise<Result<ReadonlyArray<AssessmentRecord>, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      const stmt = db.prepare("SELECT * FROM assessments ORDER BY created_at DESC");
      const rows = stmt.all() as unknown as ReadonlyArray<SqliteAssessmentRow>;
      return ok(rows.map((r) => this.rowToRecord(r)));
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "AssessmentRepository.list",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }
}

