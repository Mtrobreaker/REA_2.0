import { ok, err, type Result } from "../../../domain/result.js";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type {
  AgentRegistration,
  AgentStatus,
  IAgentRegistryRepository,
} from "../../../domain/security/blackboard/types.js";
import type { BlackboardError } from "../../../domain/security/blackboard/errors.js";
import type { SqliteBlackboardStorage } from "../SqliteBlackboardStorage.js";

interface SqliteAgentRow {
  readonly agent_id: string;
  readonly assessment_id: string;
  readonly capabilities_json: string;
  readonly host_id: string;
  readonly pid: number;
  readonly status: string;
  readonly heartbeat_at: number;
  readonly registered_at: number;
}

export class AgentRegistryRepository implements IAgentRegistryRepository {
  private readonly storage: SqliteBlackboardStorage;

  constructor(storage: SqliteBlackboardStorage) {
    this.storage = storage;
  }

  private rowToRecord(row: SqliteAgentRow): AgentRegistration {
    return {
      agent_id: row.agent_id,
      assessment_id: row.assessment_id as AssessmentId,
      capabilities: JSON.parse(row.capabilities_json),
      host_id: row.host_id,
      pid: row.pid,
      status: row.status as AgentStatus,
      heartbeat_at: row.heartbeat_at,
      registered_at: row.registered_at,
    };
  }

  public async register(agent: AgentRegistration): Promise<Result<AgentRegistration, BlackboardError>> {
    try {
      return this.storage.transaction((tx) => {
        const stmt = tx.db.prepare(`
          INSERT INTO agents (
            agent_id, assessment_id, capabilities_json, host_id, pid, status, heartbeat_at, registered_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(assessment_id, agent_id) DO UPDATE SET
            capabilities_json = excluded.capabilities_json,
            host_id = excluded.host_id,
            pid = excluded.pid,
            status = excluded.status,
            heartbeat_at = excluded.heartbeat_at
        `);

        stmt.run(
          agent.agent_id,
          agent.assessment_id,
          JSON.stringify(agent.capabilities),
          agent.host_id,
          agent.pid,
          agent.status,
          agent.heartbeat_at,
          agent.registered_at,
        );

        tx.queueOutbox("AGENT_REGISTERED", "agent", agent.agent_id, agent.assessment_id, {
          capabilities: agent.capabilities,
          host_id: agent.host_id,
          pid: agent.pid,
        });

        return ok(agent);
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "AgentRegistryRepository.register",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async heartbeat(
    assessmentId: AssessmentId,
    agentId: string,
    timestamp?: number,
  ): Promise<Result<void, BlackboardError>> {
    try {
      const now = timestamp ?? Date.now();
      const db = this.storage.getDatabase();
      const stmt = db.prepare(`
        UPDATE agents 
        SET heartbeat_at = ?, status = 'active'
        WHERE assessment_id = ? AND agent_id = ?
      `);
      stmt.run(now, assessmentId, agentId);
      return ok(undefined);
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "AgentRegistryRepository.heartbeat",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async updateStatus(
    assessmentId: AssessmentId,
    agentId: string,
    status: AgentStatus,
  ): Promise<Result<void, BlackboardError>> {
    try {
      const now = Date.now();
      const db = this.storage.getDatabase();
      const stmt = db.prepare(`
        UPDATE agents 
        SET status = ?, heartbeat_at = ?
        WHERE assessment_id = ? AND agent_id = ?
      `);
      stmt.run(status, now, assessmentId, agentId);
      return ok(undefined);
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "AgentRegistryRepository.updateStatus",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async get(
    assessmentId: AssessmentId,
    agentId: string,
  ): Promise<Result<AgentRegistration | null, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      const stmt = db.prepare("SELECT * FROM agents WHERE assessment_id = ? AND agent_id = ?");
      const row = stmt.get(assessmentId, agentId) as SqliteAgentRow | undefined;
      if (!row) {
        return ok(null);
      }
      return ok(this.rowToRecord(row));
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "AgentRegistryRepository.get",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async listActive(
    assessmentId: AssessmentId,
    maxHeartbeatAgeMs?: number,
  ): Promise<Result<ReadonlyArray<AgentRegistration>, BlackboardError>> {
    try {
      const db = this.storage.getDatabase();
      const ageThreshold = Date.now() - (maxHeartbeatAgeMs ?? 60_000);
      const stmt = db.prepare(`
        SELECT * FROM agents 
        WHERE assessment_id = ? AND heartbeat_at >= ?
        ORDER BY heartbeat_at DESC
      `);
      const rows = stmt.all(assessmentId, ageThreshold) as unknown as ReadonlyArray<SqliteAgentRow>;
      return ok(rows.map((r) => this.rowToRecord(r)));
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "AgentRegistryRepository.listActive",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }
}

