import { DatabaseSync } from "node:sqlite";
import { dirname } from "node:path";
import { mkdirSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { applyBlackboardMigrations } from "./BlackboardSchema.js";
import { KeyringManager } from "../packboard/secureKeyring.js";
import { OutboxFlusher } from "../packboard/outboxFlusher.js";
import type { ICentralBlackboard } from "../../domain/security/blackboard/types.js";
import { AssessmentRepository } from "./repositories/AssessmentRepository.js";
import { AssetRepository } from "./repositories/AssetRepository.js";
import { ObservationRepository } from "./repositories/ObservationRepository.js";
import { TaskRepository } from "./repositories/TaskRepository.js";
import { AgentRegistryRepository } from "./repositories/AgentRegistryRepository.js";
import { FindingRepository } from "./repositories/FindingRepository.js";

export interface BlackboardOptions {
  /** Path to blackboard.db. Default: ':memory:' */
  readonly dbPath?: string | undefined;
  /** Path to packboard-audit.jsonl. If provided, enables tamper-evident HMAC audit logging. */
  readonly journalPath?: string | undefined;
  /** Explicit HMAC secret key for ephemeral/testing purposes. */
  readonly hmacSecret?: string | undefined;
  /** Injected KeyringManager instance. */
  readonly keyringManager?: KeyringManager | undefined;
  /** Default assessment ID for single-assessment workspaces. */
  readonly assessmentId?: string | undefined;
  /** Maximum retries on SQLITE_BUSY / SQLITE_LOCKED contention. Default: 5 */
  readonly maxBusyRetries?: number | undefined;
}

export interface TransactionContext {
  readonly db: DatabaseSync;
  readonly inTransaction: boolean;
  queueOutbox(
    eventType: string,
    entityType: string,
    entityId: string,
    assessmentId: string,
    payload: unknown,
  ): string;
}

export class SqliteBlackboardStorage implements ICentralBlackboard {
  private readonly db: DatabaseSync;
  private readonly journalPath?: string | undefined;
  private readonly keyringManager: KeyringManager;
  private readonly flusher?: OutboxFlusher | undefined;
  private readonly maxBusyRetries: number;
  private inTransactionState = false;

  public readonly assessments: AssessmentRepository;
  public readonly assets: AssetRepository;
  public readonly observations: ObservationRepository;
  public readonly tasks: TaskRepository;
  public readonly agents: AgentRegistryRepository;
  public readonly findings: FindingRepository;

  constructor(options?: BlackboardOptions) {
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

    // Initialize typed repositories sharing this storage and transaction manager
    this.assessments = new AssessmentRepository(this);
    this.assets = new AssetRepository(this);
    this.observations = new ObservationRepository(this);
    this.tasks = new TaskRepository(this);
    this.agents = new AgentRegistryRepository(this);
    this.findings = new FindingRepository(this);
  }

  private initialize(): void {
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA synchronous = NORMAL;");
    applyBlackboardMigrations(this.db);

    if (this.flusher) {
      const reconcileRes = this.flusher.reconcileOnStartup();
      if (!reconcileRes.ok) {
        throw reconcileRes.error;
      }
    }
  }

  public getDatabase(): DatabaseSync {
    return this.db;
  }

  public getKeyringManager(): KeyringManager {
    return this.keyringManager;
  }

  public getOutboxFlusher(): OutboxFlusher | undefined {
    return this.flusher;
  }

  public close(): void {
    try {
      this.db.close();
    } catch {
      // Ignore if already closed
    }
  }

  /**
   * Executes a database operation with exponential backoff on SQLITE_BUSY or SQLITE_LOCKED.
   */
  public withBusyRetry<T>(operation: () => T): T {
    let delay = 30;
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
          delay = Math.min(delay * 1.5, 400);
          continue;
        }
        throw error;
      }
    }
    throw new Error(`Exceeded maximum busy retries (${this.maxBusyRetries})`);
  }

  /**
   * Executes an operation inside a single atomic SQLite transaction (BEGIN IMMEDIATE ... COMMIT).
   * Automatically queues outbox events and triggers outbox flushing upon successful commit.
   * If an inner transaction is invoked, participates in the existing transaction context.
   */
  public transaction<T>(operation: (tx: TransactionContext) => T): T {
    if (this.inTransactionState) {
      // Re-entrant / nested participation
      const tx: TransactionContext = {
        db: this.db,
        inTransaction: true,
        queueOutbox: (eventType, entityType, entityId, assessmentId, payload) =>
          this.queueOutboxInternal(eventType, entityType, entityId, assessmentId, payload),
      };
      return operation(tx);
    }

    return this.withBusyRetry(() => {
      this.db.exec("BEGIN IMMEDIATE;");
      this.inTransactionState = true;

      const tx: TransactionContext = {
        db: this.db,
        inTransaction: true,
        queueOutbox: (eventType, entityType, entityId, assessmentId, payload) =>
          this.queueOutboxInternal(eventType, entityType, entityId, assessmentId, payload),
      };

      try {
        const result = operation(tx);
        this.db.exec("COMMIT;");
        this.inTransactionState = false;

        // Drain outbox post-commit
        if (this.flusher) {
          this.flusher.drainOutbox();
        }

        return result;
      } catch (error) {
        try {
          this.db.exec("ROLLBACK;");
        } catch {
          // Ignore rollback error
        }
        this.inTransactionState = false;
        throw error;
      }
    });
  }

  private queueOutboxInternal(
    eventType: string,
    entityType: string,
    entityId: string,
    assessmentId: string,
    payload: unknown,
  ): string {
    const eventId = randomUUID();
    const now = Date.now();
    const insertStmt = this.db.prepare(`
      INSERT INTO transactional_outbox (
        event_id, event_type, entity_type, entity_id, assessment_id, payload_json, created_at, flushed
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    `);
    insertStmt.run(eventId, eventType, entityType, entityId, assessmentId, JSON.stringify(payload), now);
    return eventId;
  }
}

