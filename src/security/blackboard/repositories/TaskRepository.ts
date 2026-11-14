import { ok, err, type Result } from "../../../domain/result.js";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { AssetId } from "../../../domain/security/asset.js";
import type {
  TaskRecord,
  TaskClaim,
  TaskFilter,
  TaskPriority,
  TaskStatus,
  ITaskRepository,
} from "../../../domain/security/blackboard/types.js";
import { nextFencingToken, validateFencingToken } from "../../../domain/security/blackboard/fencingToken.js";
import type { BlackboardError } from "../../../domain/security/blackboard/errors.js";
import type { SqliteBlackboardStorage } from "../SqliteBlackboardStorage.js";

interface SqliteTaskRow {
  readonly id: string;
  readonly assessment_id: string;
  readonly task_type: string;
  readonly title: string;
  readonly description: string;
  readonly asset_id: string;
  readonly priority: string;
  readonly status: string;
  readonly blocked_by_json: string;
  readonly fencing_token: number;
  readonly cas_version: number;
  readonly claim_json: string | null;
  readonly result_json: string | null;
  readonly metadata_json: string;
  readonly fingerprint: string | null;
  readonly location_json: string | null;
  readonly classification_json: string | null;
  readonly severity: string | null;
  readonly confidence: string | null;
  readonly smoke_score: number;
  readonly provenance: string | null;
  readonly votes_json: string;
  readonly evidence_hashes_json: string;
  readonly created_at: number;
  readonly updated_at: number;
}

export class TaskRepository implements ITaskRepository {
  private readonly storage: SqliteBlackboardStorage;

  constructor(storage: SqliteBlackboardStorage) {
    this.storage = storage;
  }

  private rowToRecord(row: SqliteTaskRow): TaskRecord {
    return {
      id: row.id,
      assessment_id: row.assessment_id as AssessmentId,
      task_type: row.task_type,
      title: row.title,
      description: row.description,
      asset_id: row.asset_id as AssetId,
      priority: row.priority as TaskPriority,
      status: row.status as TaskStatus,
      blocked_by: JSON.parse(row.blocked_by_json),
      fencing_token: row.fencing_token,
      cas_version: row.cas_version,
      claim: row.claim_json ? JSON.parse(row.claim_json) : null,
      result: row.result_json ? JSON.parse(row.result_json) : null,
      metadata: JSON.parse(row.metadata_json),
      fingerprint: row.fingerprint ?? undefined,
      location: row.location_json ? JSON.parse(row.location_json) : undefined,
      classification: row.classification_json ? JSON.parse(row.classification_json) : undefined,
      severity: row.severity ?? undefined,
      confidence: row.confidence ?? undefined,
      smoke_score: row.smoke_score,
      provenance: row.provenance ?? undefined,
      votes: JSON.parse(row.votes_json),
      evidence_hashes: JSON.parse(row.evidence_hashes_json),
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  public async create(task: TaskRecord): Promise<Result<TaskRecord, BlackboardError>> {
    try {
      return this.storage.transaction((tx) => {
        // If task has dependencies, verify if any are unresolved to set initial status
        let initialStatus = task.status;
        if (task.blocked_by && task.blocked_by.length > 0 && initialStatus === "open") {
          const unresolved = this.checkUnresolvedDependencies(tx.db, task.assessment_id, task.blocked_by);
          if (unresolved.length > 0) {
            initialStatus = "blocked";
          }
        }

        const taskToInsert: TaskRecord = {
          ...task,
          status: initialStatus,
        };

        const stmt = tx.db.prepare(`
          INSERT INTO tasks (
            id, assessment_id, task_type, title, description, asset_id, priority, status,
            blocked_by_json, fencing_token, cas_version, claim_json, result_json, metadata_json,
            fingerprint, location_json, classification_json, severity, confidence, smoke_score,
            provenance, votes_json, evidence_hashes_json, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        stmt.run(
          taskToInsert.id,
          taskToInsert.assessment_id,
          taskToInsert.task_type,
          taskToInsert.title,
          taskToInsert.description,
          taskToInsert.asset_id,
          taskToInsert.priority,
          taskToInsert.status,
          JSON.stringify(taskToInsert.blocked_by ?? []),
          taskToInsert.fencing_token ?? 1,
          taskToInsert.cas_version ?? 1,
          taskToInsert.claim ? JSON.stringify(taskToInsert.claim) : null,
          taskToInsert.result ? JSON.stringify(taskToInsert.result) : null,
          JSON.stringify(taskToInsert.metadata ?? {}),
          taskToInsert.fingerprint ?? null,
          taskToInsert.location ? JSON.stringify(taskToInsert.location) : null,
          taskToInsert.classification ? JSON.stringify(taskToInsert.classification) : null,
          taskToInsert.severity ?? null,
          taskToInsert.confidence ?? null,
          taskToInsert.smoke_score ?? 1,
          taskToInsert.provenance ?? null,
          JSON.stringify(taskToInsert.votes ?? []),
          JSON.stringify(taskToInsert.evidence_hashes ?? []),
          taskToInsert.created_at,
          taskToInsert.updated_at,
        );

        tx.queueOutbox("TASK_CREATED", "task", taskToInsert.id, taskToInsert.assessment_id, {
          title: taskToInsert.title,
          task_type: taskToInsert.task_type,
          status: taskToInsert.status,
          priority: taskToInsert.priority,
          blocked_by: taskToInsert.blocked_by,
        });

        return ok(taskToInsert);
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "TaskRepository.create",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async getById(
    assessmentId: AssessmentId,
    taskId: string,
  ): Promise<Result<TaskRecord | null, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      const stmt = db.prepare("SELECT * FROM tasks WHERE assessment_id = ? AND id = ?");
      const row = stmt.get(assessmentId, taskId) as SqliteTaskRow | undefined;
      if (!row) {
        return ok(null);
      }
      return ok(this.rowToRecord(row));
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "TaskRepository.getById",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  private checkUnresolvedDependencies(
    db: any,
    assessmentId: string,
    dependencies: readonly string[],
  ): string[] {
    const unresolved: string[] = [];
    for (const depId of dependencies) {
      const depStmt = db.prepare("SELECT status FROM tasks WHERE assessment_id = ? AND id = ?");
      const row = depStmt.get(assessmentId, depId) as { status: string } | undefined;
      if (!row || (row.status !== "completed" && row.status !== "verified")) {
        unresolved.push(depId);
      }
    }
    return unresolved;
  }

  public async claimTask(
    assessmentId: AssessmentId,
    taskId: string,
    claim: TaskClaim,
    expectedCasVersion: number,
  ): Promise<Result<TaskRecord, BlackboardError>> {
    try {
      return this.storage.transaction((tx) => {
        const findStmt = tx.db.prepare("SELECT * FROM tasks WHERE assessment_id = ? AND id = ?");
        const row = findStmt.get(assessmentId, taskId) as SqliteTaskRow | undefined;
        if (!row) {
          return err({
            code: "TASK_NOT_FOUND",
            taskId,
            message: `Task ${taskId} not found in assessment ${assessmentId}`,
          });
        }

        const task = this.rowToRecord(row);

        // 1. Dependency gate: task cannot be claimed if blocked
        if (task.blocked_by && task.blocked_by.length > 0) {
          const unresolved = this.checkUnresolvedDependencies(tx.db, assessmentId, task.blocked_by);
          if (unresolved.length > 0) {
            return err({
              code: "TASK_BLOCKED",
              taskId,
              unresolvedDependencies: unresolved,
              message: `Task ${taskId} cannot be claimed; blocked by unresolved dependencies: ${unresolved.join(", ")}`,
            });
          }
        }

        // 2. CAS version verification
        if (task.cas_version !== expectedCasVersion) {
          return err({
            code: "CAS_CONFLICT",
            entityId: taskId,
            expectedVersion: expectedCasVersion,
            actualVersion: task.cas_version,
            currentEntity: task,
            message: `CAS version mismatch on task ${taskId}: expected ${expectedCasVersion}, actual ${task.cas_version}`,
          });
        }

        // 3. Atomically increment fencing token and cas_version
        const newFencingToken = nextFencingToken(task.fencing_token);
        const newCasVersion = task.cas_version + 1;
        const now = Date.now();

        const updateStmt = tx.db.prepare(`
          UPDATE tasks
          SET status = 'claimed',
              claim_json = ?,
              fencing_token = ?,
              cas_version = ?,
              updated_at = ?
          WHERE assessment_id = ? AND id = ? AND cas_version = ?
        `);

        const res = updateStmt.run(
          JSON.stringify(claim),
          newFencingToken,
          newCasVersion,
          now,
          assessmentId,
          taskId,
          expectedCasVersion,
        );

        if (res.changes === 0) {
          // Concurrent race lost
          const fresh = findStmt.get(assessmentId, taskId) as unknown as SqliteTaskRow;
          const freshTask = this.rowToRecord(fresh);
          return err({
            code: "CAS_CONFLICT",
            entityId: taskId,
            expectedVersion: expectedCasVersion,
            actualVersion: freshTask.cas_version,
            currentEntity: freshTask,
            message: `Concurrent modification on task ${taskId}`,
          });
        }

        const updated: TaskRecord = {
          ...task,
          status: "claimed",
          claim,
          fencing_token: newFencingToken,
          cas_version: newCasVersion,
          updated_at: now,
        };

        tx.queueOutbox("TASK_CLAIMED", "task", taskId, assessmentId, {
          agent_id: claim.agent_id,
          fencing_token: newFencingToken,
          lease_until: claim.lease_until,
        });

        return ok(updated);
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "TaskRepository.claimTask",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async completeTask(
    assessmentId: AssessmentId,
    taskId: string,
    fencingToken: number,
    result?: unknown,
  ): Promise<Result<TaskRecord, BlackboardError>> {
    try {
      return this.storage.transaction((tx) => {
        const findStmt = tx.db.prepare("SELECT * FROM tasks WHERE assessment_id = ? AND id = ?");
        const row = findStmt.get(assessmentId, taskId) as SqliteTaskRow | undefined;
        if (!row) {
          return err({
            code: "TASK_NOT_FOUND",
            taskId,
            message: `Task ${taskId} not found`,
          });
        }

        const task = this.rowToRecord(row);

        // Fencing token validation: Reject stale / zombie workers
        if (!validateFencingToken(task.fencing_token, fencingToken)) {
          return err({
            code: "STALE_FENCING_TOKEN",
            taskId,
            expectedToken: task.fencing_token,
            submittedToken: fencingToken,
            message: `Rejected mutation from stale worker: active token is ${task.fencing_token}, submitted token was ${fencingToken}`,
          });
        }

        const now = Date.now();
        const newCasVersion = task.cas_version + 1;

        const updateStmt = tx.db.prepare(`
          UPDATE tasks
          SET status = 'completed',
              result_json = ?,
              cas_version = ?,
              updated_at = ?
          WHERE assessment_id = ? AND id = ?
        `);
        updateStmt.run(result ? JSON.stringify(result) : null, newCasVersion, now, assessmentId, taskId);

        const updated: TaskRecord = {
          ...task,
          status: "completed",
          result: result ?? null,
          cas_version: newCasVersion,
          updated_at: now,
        };

        tx.queueOutbox("TASK_COMPLETED", "task", taskId, assessmentId, {
          fencing_token: fencingToken,
          result,
        });

        // Automatically unblock downstream tasks in this assessment whose dependencies are now met
        this.unblockDependentTasks(tx.db, assessmentId, taskId);

        return ok(updated);
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "TaskRepository.completeTask",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  private unblockDependentTasks(db: any, assessmentId: string, completedTaskId: string): void {
    const blockedStmt = db.prepare(
      "SELECT * FROM tasks WHERE assessment_id = ? AND status = 'blocked'",
    );
    const blockedRows = blockedStmt.all(assessmentId) as unknown as ReadonlyArray<SqliteTaskRow>;

    for (const bRow of blockedRows) {
      const bTask = this.rowToRecord(bRow);
      if (bTask.blocked_by.includes(completedTaskId)) {
        const remaining = this.checkUnresolvedDependencies(db, assessmentId, bTask.blocked_by);
        if (remaining.length === 0) {
          // All dependencies satisfied! Unblock task
          db.prepare(`
            UPDATE tasks
            SET status = 'open', cas_version = cas_version + 1, updated_at = ?
            WHERE assessment_id = ? AND id = ?
          `).run(Date.now(), assessmentId, bTask.id);
        }
      }
    }
  }

  public async failTask(
    assessmentId: AssessmentId,
    taskId: string,
    fencingToken: number,
    errorReason: string,
  ): Promise<Result<TaskRecord, BlackboardError>> {
    try {
      return this.storage.transaction((tx) => {
        const findStmt = tx.db.prepare("SELECT * FROM tasks WHERE assessment_id = ? AND id = ?");
        const row = findStmt.get(assessmentId, taskId) as SqliteTaskRow | undefined;
        if (!row) {
          return err({
            code: "TASK_NOT_FOUND",
            taskId,
            message: `Task ${taskId} not found`,
          });
        }

        const task = this.rowToRecord(row);

        if (!validateFencingToken(task.fencing_token, fencingToken)) {
          return err({
            code: "STALE_FENCING_TOKEN",
            taskId,
            expectedToken: task.fencing_token,
            submittedToken: fencingToken,
            message: `Rejected mutation from stale worker: active token is ${task.fencing_token}, submitted token was ${fencingToken}`,
          });
        }

        const now = Date.now();
        const newCasVersion = task.cas_version + 1;

        const updateStmt = tx.db.prepare(`
          UPDATE tasks
          SET status = 'failed',
              result_json = ?,
              cas_version = ?,
              updated_at = ?
          WHERE assessment_id = ? AND id = ?
        `);
        updateStmt.run(JSON.stringify({ error: errorReason }), newCasVersion, now, assessmentId, taskId);

        const updated: TaskRecord = {
          ...task,
          status: "failed",
          result: { error: errorReason },
          cas_version: newCasVersion,
          updated_at: now,
        };

        tx.queueOutbox("TASK_FAILED", "task", taskId, assessmentId, {
          fencing_token: fencingToken,
          error: errorReason,
        });

        return ok(updated);
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "TaskRepository.failTask",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async updateResult(
    assessmentId: AssessmentId,
    taskId: string,
    fencingToken: number,
    result: unknown,
  ): Promise<Result<TaskRecord, BlackboardError>> {
    try {
      return this.storage.transaction((tx) => {
        const findStmt = tx.db.prepare("SELECT * FROM tasks WHERE assessment_id = ? AND id = ?");
        const row = findStmt.get(assessmentId, taskId) as SqliteTaskRow | undefined;
        if (!row) {
          return err({
            code: "TASK_NOT_FOUND",
            taskId,
            message: `Task ${taskId} not found`,
          });
        }

        const task = this.rowToRecord(row);

        if (!validateFencingToken(task.fencing_token, fencingToken)) {
          return err({
            code: "STALE_FENCING_TOKEN",
            taskId,
            expectedToken: task.fencing_token,
            submittedToken: fencingToken,
            message: `Rejected mutation from stale worker: active token is ${task.fencing_token}, submitted token was ${fencingToken}`,
          });
        }

        const now = Date.now();
        const newCasVersion = task.cas_version + 1;

        const updateStmt = tx.db.prepare(`
          UPDATE tasks
          SET result_json = ?,
              cas_version = ?,
              updated_at = ?
          WHERE assessment_id = ? AND id = ?
        `);
        updateStmt.run(result ? JSON.stringify(result) : null, newCasVersion, now, assessmentId, taskId);

        const updated: TaskRecord = {
          ...task,
          result: result ?? null,
          cas_version: newCasVersion,
          updated_at: now,
        };

        tx.queueOutbox("TASK_RESULT_UPDATED", "task", taskId, assessmentId, {
          fencing_token: fencingToken,
          result,
        });

        return ok(updated);
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "TaskRepository.updateResult",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async reapExpiredLeases(
    assessmentId: AssessmentId,
    now: number,
  ): Promise<Result<number, BlackboardError>> {
    try {
      return this.storage.transaction((tx) => {
        const findStmt = tx.db.prepare(`
          SELECT * FROM tasks 
          WHERE assessment_id = ? AND status = 'claimed'
        `);
        const rows = findStmt.all(assessmentId) as unknown as ReadonlyArray<SqliteTaskRow>;

        let reapedCount = 0;
        const updateStmt = tx.db.prepare(`
          UPDATE tasks
          SET status = 'open',
              claim_json = NULL,
              fencing_token = fencing_token + 1,
              cas_version = cas_version + 1,
              updated_at = ?
          WHERE assessment_id = ? AND id = ? AND cas_version = ?
        `);

        for (const row of rows) {
          if (!row.claim_json) continue;
          const claim = JSON.parse(row.claim_json) as TaskClaim;
          if (claim.lease_until < now) {
            const res = updateStmt.run(now, assessmentId, row.id, row.cas_version);
            if (res.changes > 0) {
              reapedCount++;
              tx.queueOutbox("TASK_LEASE_REAPED", "task", row.id, assessmentId, {
                reaped_at: now,
                crashed_agent_id: claim.agent_id,
                new_fencing_token: row.fencing_token + 1,
              });
            }
          }
        }

        return ok(reapedCount);
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "TaskRepository.reapExpiredLeases",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async renewLease(
    assessmentId: AssessmentId,
    taskId: string,
    agentId: string,
    fencingToken: number,
    extensionMs: number,
    maxRenewals = 5,
  ): Promise<Result<TaskRecord, BlackboardError>> {
    try {
      return this.storage.transaction((tx) => {
        const findStmt = tx.db.prepare("SELECT * FROM tasks WHERE assessment_id = ? AND id = ?");
        const row = findStmt.get(assessmentId, taskId) as SqliteTaskRow | undefined;
        if (!row) {
          return err({
            code: "TASK_NOT_FOUND",
            taskId,
            message: `Task ${taskId} not found`,
          });
        }

        const task = this.rowToRecord(row);

        if (!validateFencingToken(task.fencing_token, fencingToken)) {
          return err({
            code: "STALE_FENCING_TOKEN",
            taskId,
            expectedToken: task.fencing_token,
            submittedToken: fencingToken,
            message: `Rejected lease renewal from stale worker: active token is ${task.fencing_token}, submitted was ${fencingToken}`,
          });
        }

        if (!task.claim || task.claim.agent_id !== agentId) {
          return err({
            code: "STORAGE_ERROR",
            operation: "TaskRepository.renewLease",
            message: `Task ${taskId} is not claimed by agent ${agentId}`,
          });
        }

        const currentRenewals = (task.metadata.renewal_count as number | undefined) ?? 0;
        if (currentRenewals >= maxRenewals) {
          return err({
            code: "LEASE_RENEWAL_EXCEEDED",
            taskId,
            renewals: currentRenewals,
            maxRenewals,
            message: `Task ${taskId} reached maximum lease renewal ceiling (${maxRenewals})`,
          });
        }

        const now = Date.now();
        const newLeaseUntil = now + extensionMs;
        const newClaim: TaskClaim = {
          ...task.claim,
          lease_until: newLeaseUntil,
        };
        const newMetadata = {
          ...task.metadata,
          renewal_count: currentRenewals + 1,
          last_renewed_at: now,
        };

        const updateStmt = tx.db.prepare(`
          UPDATE tasks
          SET claim_json = ?,
              metadata_json = ?,
              updated_at = ?
          WHERE assessment_id = ? AND id = ?
        `);
        updateStmt.run(JSON.stringify(newClaim), JSON.stringify(newMetadata), now, assessmentId, taskId);

        const updated: TaskRecord = {
          ...task,
          claim: newClaim,
          metadata: newMetadata,
          updated_at: now,
        };

        tx.queueOutbox("TASK_LEASE_RENEWED", "task", taskId, assessmentId, {
          agent_id: agentId,
          fencing_token: fencingToken,
          lease_until: newLeaseUntil,
          renewal_count: currentRenewals + 1,
        });

        return ok(updated);
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "TaskRepository.renewLease",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async retryTask(
    assessmentId: AssessmentId,
    taskId: string,
    reason: string,
    maxRetries = 3,
  ): Promise<Result<{ task: TaskRecord; deadLetter: boolean }, BlackboardError>> {
    try {
      return this.storage.transaction((tx) => {
        const findStmt = tx.db.prepare("SELECT * FROM tasks WHERE assessment_id = ? AND id = ?");
        const row = findStmt.get(assessmentId, taskId) as SqliteTaskRow | undefined;
        if (!row) {
          return err({
            code: "TASK_NOT_FOUND",
            taskId,
            message: `Task ${taskId} not found`,
          });
        }

        const task = this.rowToRecord(row);
        const currentRetries = (task.metadata.retry_count as number | undefined) ?? 0;
        const nextRetryCount = currentRetries + 1;
        const now = Date.now();
        const newCasVersion = task.cas_version + 1;

        if (nextRetryCount > maxRetries) {
          // Dead-letter exhausted retries
          const deadLetterMetadata = {
            ...task.metadata,
            retry_count: nextRetryCount,
            dead_letter: true,
            exhausted_reason: reason,
          };
          const deadLetterResult = {
            error: reason,
            dead_letter: true,
            retries_exhausted: true,
            attempts: nextRetryCount,
          };

          tx.db.prepare(`
            UPDATE tasks
            SET status = 'failed',
                result_json = ?,
                metadata_json = ?,
                cas_version = ?,
                updated_at = ?
            WHERE assessment_id = ? AND id = ?
          `).run(JSON.stringify(deadLetterResult), JSON.stringify(deadLetterMetadata), newCasVersion, now, assessmentId, taskId);

          const updated: TaskRecord = {
            ...task,
            status: "failed",
            result: deadLetterResult,
            metadata: deadLetterMetadata,
            cas_version: newCasVersion,
            updated_at: now,
          };

          tx.queueOutbox("TASK_DEAD_LETTERED", "task", taskId, assessmentId, {
            retries: nextRetryCount,
            reason,
          });

          return ok({ task: updated, deadLetter: true });
        }

        // Re-open for retry with incremented fencing token to invalidate previous workers
        const newFencingToken = task.fencing_token + 1;
        const retryMetadata = {
          ...task.metadata,
          retry_count: nextRetryCount,
          last_retry_reason: reason,
          renewal_count: 0,
        };

        tx.db.prepare(`
          UPDATE tasks
          SET status = 'open',
              claim_json = NULL,
              fencing_token = ?,
              metadata_json = ?,
              cas_version = ?,
              updated_at = ?
          WHERE assessment_id = ? AND id = ?
        `).run(newFencingToken, JSON.stringify(retryMetadata), newCasVersion, now, assessmentId, taskId);

        const updated: TaskRecord = {
          ...task,
          status: "open",
          claim: null,
          fencing_token: newFencingToken,
          metadata: retryMetadata,
          cas_version: newCasVersion,
          updated_at: now,
        };

        tx.queueOutbox("TASK_RETRIED", "task", taskId, assessmentId, {
          retry_count: nextRetryCount,
          new_fencing_token: newFencingToken,
          reason,
        });

        return ok({ task: updated, deadLetter: false });
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "TaskRepository.retryTask",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async listByAssessment(
    assessmentId: AssessmentId,
    filter?: TaskFilter,
  ): Promise<Result<ReadonlyArray<TaskRecord>, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      let sql = "SELECT * FROM tasks WHERE assessment_id = ?";
      const params: any[] = [assessmentId];

      if (filter?.status) {
        sql += " AND status = ?";
        params.push(filter.status);
      }
      if (filter?.task_type) {
        sql += " AND task_type = ?";
        params.push(filter.task_type);
      }
      if (filter?.asset_id) {
        sql += " AND asset_id = ?";
        params.push(filter.asset_id);
      }
      sql += " ORDER BY created_at ASC";

      const stmt = db.prepare(sql);
      const rows = stmt.all(...params) as unknown as ReadonlyArray<SqliteTaskRow>;

      let records = rows.map((r) => this.rowToRecord(r));
      if (filter?.agent_id) {
        records = records.filter((r) => r.claim?.agent_id === filter.agent_id);
      }

      return ok(records);
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "TaskRepository.listByAssessment",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }
}
