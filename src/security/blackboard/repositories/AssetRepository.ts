import { ok, err, type Result } from "../../../domain/result.js";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { AssetId, AssetType } from "../../../domain/security/asset.js";
import type {
  BlackboardAssetRecord,
  IAssetRepository,
} from "../../../domain/security/blackboard/types.js";
import type { BlackboardError } from "../../../domain/security/blackboard/errors.js";
import type { SqliteBlackboardStorage } from "../SqliteBlackboardStorage.js";

interface SqliteAssetRow {
  readonly id: string;
  readonly assessment_id: string;
  readonly parent_asset_id: string | null;
  readonly name: string;
  readonly type: string;
  readonly path: string | null;
  readonly sha256: string | null;
  readonly architecture: string | null;
  readonly version: string | null;
  readonly environment_json: string | null;
  readonly tags_json: string;
  readonly metadata_json: string;
  readonly created_at: number;
}

export class AssetRepository implements IAssetRepository {
  private readonly storage: SqliteBlackboardStorage;

  constructor(storage: SqliteBlackboardStorage) {
    this.storage = storage;
  }

  private rowToRecord(row: SqliteAssetRow): BlackboardAssetRecord {
    return {
      id: row.id as AssetId,
      assessment_id: row.assessment_id as AssessmentId,
      parent_asset_id: row.parent_asset_id as AssetId | null,
      name: row.name,
      type: row.type as AssetType,
      path: row.path,
      digest: row.sha256 ? { sha256: row.sha256 } : null,
      architecture: row.architecture,
      version: row.version,
      environment: row.environment_json ? JSON.parse(row.environment_json) : null,
      tags: JSON.parse(row.tags_json),
      metadata: JSON.parse(row.metadata_json),
      created_at: row.created_at,
    };
  }

  public async create(
    asset: BlackboardAssetRecord,
  ): Promise<Result<BlackboardAssetRecord, BlackboardError>> {
    try {
      return this.storage.transaction((tx) => {
        const stmt = tx.db.prepare(`
          INSERT INTO assets (
            id, assessment_id, parent_asset_id, name, type, path, sha256,
            architecture, version, environment_json, tags_json, metadata_json, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(
          asset.id,
          asset.assessment_id,
          asset.parent_asset_id,
          asset.name,
          asset.type,
          asset.path,
          asset.digest?.sha256 ?? null,
          asset.architecture,
          asset.version,
          asset.environment ? JSON.stringify(asset.environment) : null,
          JSON.stringify(asset.tags),
          JSON.stringify(asset.metadata),
          asset.created_at,
        );

        tx.queueOutbox("ASSET_CREATED", "asset", asset.id, asset.assessment_id, {
          name: asset.name,
          type: asset.type,
          parent_asset_id: asset.parent_asset_id,
          sha256: asset.digest?.sha256 ?? null,
        });

        return ok(asset);
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "AssetRepository.create",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async findById(
    assessmentId: AssessmentId,
    id: AssetId,
  ): Promise<Result<BlackboardAssetRecord | null, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      const stmt = db.prepare("SELECT * FROM assets WHERE assessment_id = ? AND id = ?");
      const row = stmt.get(assessmentId, id) as SqliteAssetRow | undefined;
      if (!row) {
        return ok(null);
      }
      return ok(this.rowToRecord(row));
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "AssetRepository.findById",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async findByParent(
    assessmentId: AssessmentId,
    parentId: AssetId,
  ): Promise<Result<ReadonlyArray<BlackboardAssetRecord>, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      const stmt = db.prepare(
        "SELECT * FROM assets WHERE assessment_id = ? AND parent_asset_id = ? ORDER BY created_at ASC",
      );
      const rows = stmt.all(assessmentId, parentId) as unknown as ReadonlyArray<SqliteAssetRow>;
      return ok(rows.map((r) => this.rowToRecord(r)));
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "AssetRepository.findByParent",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async listByAssessment(
    assessmentId: AssessmentId,
    filter?: { readonly type?: AssetType },
  ): Promise<Result<ReadonlyArray<BlackboardAssetRecord>, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      let query = "SELECT * FROM assets WHERE assessment_id = ?";
      const params: any[] = [assessmentId];

      if (filter?.type) {
        query += " AND type = ?";
        params.push(filter.type);
      }
      query += " ORDER BY created_at ASC";

      const stmt = db.prepare(query);
      const rows = stmt.all(...params) as unknown as ReadonlyArray<SqliteAssetRow>;
      return ok(rows.map((r) => this.rowToRecord(r)));
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "AssetRepository.listByAssessment",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }
}

