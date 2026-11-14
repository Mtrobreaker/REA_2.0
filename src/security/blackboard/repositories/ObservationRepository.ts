import { randomUUID } from "node:crypto";
import { ok, err, type Result } from "../../../domain/result.js";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { AssetId } from "../../../domain/security/asset.js";
import type {
  ObservationRecord,
  ObservationConflictGroup,
  IObservationRepository,
} from "../../../domain/security/blackboard/types.js";
import type { BlackboardError } from "../../../domain/security/blackboard/errors.js";
import type { SqliteBlackboardStorage } from "../SqliteBlackboardStorage.js";

interface SqliteObservationRow {
  readonly id: string;
  readonly assessment_id: string;
  readonly asset_id: string;
  readonly key: string;
  readonly value_json: string;
  readonly confidence: number;
  readonly source_tool: string;
  readonly agent_id: string;
  readonly evidence_id: string | null;
  readonly created_at: number;
}

export class ObservationRepository implements IObservationRepository {
  private readonly storage: SqliteBlackboardStorage;

  constructor(storage: SqliteBlackboardStorage) {
    this.storage = storage;
  }

  private rowToRecord(row: SqliteObservationRow, isConflict?: boolean): ObservationRecord {
    return {
      id: row.id,
      assessment_id: row.assessment_id as AssessmentId,
      asset_id: row.asset_id as AssetId,
      key: row.key,
      value: JSON.parse(row.value_json),
      confidence: row.confidence,
      source_tool: row.source_tool,
      agent_id: row.agent_id,
      evidence_id: row.evidence_id,
      ...(isConflict !== undefined ? { is_conflict: isConflict } : {}),
      created_at: row.created_at,
    };
  }

  public async record(
    observation: Omit<ObservationRecord, "id" | "is_conflict">,
  ): Promise<Result<ObservationRecord, BlackboardError>> {
    try {
      const id = `obs_${randomUUID()}`;
      const recordToSave: ObservationRecord = {
        ...observation,
        id,
      };

      return this.storage.transaction((tx) => {
        // 1. Check existing observations for this (asset_id, key) to detect conflicts
        const checkStmt = tx.db.prepare(`
          SELECT * FROM observations 
          WHERE assessment_id = ? AND asset_id = ? AND key = ?
        `);
        const existingRows = checkStmt.all(
          observation.assessment_id,
          observation.asset_id,
          observation.key,
        ) as unknown as ReadonlyArray<SqliteObservationRow>;

        const serializedNewValue = JSON.stringify(observation.value);
        let hasConflict = false;

        for (const prev of existingRows) {
          if (prev.value_json !== serializedNewValue) {
            hasConflict = true;
            break;
          }
        }

        // 2. Insert new observation without overwriting previous observations
        const insertStmt = tx.db.prepare(`
          INSERT INTO observations (
            id, assessment_id, asset_id, key, value_json, confidence,
            source_tool, agent_id, evidence_id, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        insertStmt.run(
          id,
          observation.assessment_id,
          observation.asset_id,
          observation.key,
          serializedNewValue,
          observation.confidence,
          observation.source_tool,
          observation.agent_id,
          observation.evidence_id ?? null,
          observation.created_at,
        );

        // 3. Queue outbox event
        tx.queueOutbox("OBSERVATION_RECORDED", "observation", id, observation.assessment_id, {
          asset_id: observation.asset_id,
          key: observation.key,
          value: observation.value,
          confidence: observation.confidence,
          source_tool: observation.source_tool,
          agent_id: observation.agent_id,
          has_conflict: hasConflict,
        });

        if (hasConflict) {
          tx.queueOutbox("OBSERVATION_CONFLICT_DETECTED", "observation", id, observation.assessment_id, {
            asset_id: observation.asset_id,
            key: observation.key,
            new_value: observation.value,
            previous_values: existingRows.map((r) => ({
              agent_id: r.agent_id,
              source_tool: r.source_tool,
              value: JSON.parse(r.value_json),
              confidence: r.confidence,
            })),
          });
        }

        return ok({
          ...recordToSave,
          is_conflict: hasConflict,
        });
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "ObservationRepository.record",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async findById(
    assessmentId: AssessmentId,
    id: string,
  ): Promise<Result<ObservationRecord | null, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      const stmt = db.prepare("SELECT * FROM observations WHERE assessment_id = ? AND id = ?");
      const row = stmt.get(assessmentId, id) as SqliteObservationRow | undefined;
      if (!row) {
        return ok(null);
      }
      return ok(this.rowToRecord(row));
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "ObservationRepository.findById",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async listByAsset(
    assessmentId: AssessmentId,
    assetId: AssetId,
    key?: string,
  ): Promise<Result<ReadonlyArray<ObservationRecord>, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      let sql = "SELECT * FROM observations WHERE assessment_id = ? AND asset_id = ?";
      const params: any[] = [assessmentId, assetId];

      if (key !== undefined) {
        sql += " AND key = ?";
        params.push(key);
      }
      sql += " ORDER BY created_at ASC";

      const stmt = db.prepare(sql);
      const rows = stmt.all(...params) as unknown as ReadonlyArray<SqliteObservationRow>;

      // Determine conflicts
      const valueMap = new Map<string, Set<string>>();
      for (const r of rows) {
        if (!valueMap.has(r.key)) {
          valueMap.set(r.key, new Set());
        }
        valueMap.get(r.key)!.add(r.value_json);
      }

      return ok(
        rows.map((r) => {
          const isConflict = (valueMap.get(r.key)?.size ?? 0) > 1;
          return this.rowToRecord(r, isConflict);
        }),
      );
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "ObservationRepository.listByAsset",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async getConflicts(
    assessmentId: AssessmentId,
    assetId?: AssetId,
  ): Promise<Result<ReadonlyArray<ObservationConflictGroup>, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      let sql = `
        SELECT o.* FROM observations o
        INNER JOIN (
          SELECT assessment_id, asset_id, key
          FROM observations
          WHERE assessment_id = ?
          GROUP BY assessment_id, asset_id, key
          HAVING COUNT(DISTINCT value_json) > 1
        ) c ON o.assessment_id = c.assessment_id AND o.asset_id = c.asset_id AND o.key = c.key
      `;
      const params: any[] = [assessmentId];

      if (assetId !== undefined) {
        sql += " WHERE o.asset_id = ?";
        params.push(assetId);
      }
      sql += " ORDER BY o.asset_id, o.key, o.created_at ASC";

      const stmt = db.prepare(sql);
      const rows = stmt.all(...params) as unknown as ReadonlyArray<SqliteObservationRow>;

      const groupMap = new Map<string, { asset_id: AssetId; key: string; observations: ObservationRecord[] }>();

      for (const row of rows) {
        const groupKey = `${row.asset_id}::${row.key}`;
        if (!groupMap.has(groupKey)) {
          groupMap.set(groupKey, {
            asset_id: row.asset_id as AssetId,
            key: row.key,
            observations: [],
          });
        }
        groupMap.get(groupKey)!.observations.push(this.rowToRecord(row, true));
      }

      return ok(Array.from(groupMap.values()));
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "ObservationRepository.getConflicts",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }
}

