import type { DatabaseSync } from "node:sqlite";

export const BLACKBOARD_CURRENT_SCHEMA_VERSION = 2;

export const BLACKBOARD_SCHEMA_DDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL
);

-- 1. Assessments
CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  objective_json TEXT NOT NULL,
  authorization_json TEXT NOT NULL,
  metrics_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assessments_status ON assessments(status);

-- 2. Assets (target hierarchy)
CREATE TABLE IF NOT EXISTS assets (
  id TEXT NOT NULL,
  assessment_id TEXT NOT NULL,
  parent_asset_id TEXT,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  path TEXT,
  sha256 TEXT,
  architecture TEXT,
  version TEXT,
  environment_json TEXT,
  tags_json TEXT NOT NULL DEFAULT '[]',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  PRIMARY KEY(assessment_id, id),
  FOREIGN KEY(assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_assets_assessment ON assets(assessment_id);
CREATE INDEX IF NOT EXISTS idx_assets_parent ON assets(assessment_id, parent_asset_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(assessment_id, type);

-- 3. Observations (conflict-preserving facts with provenance)
CREATE TABLE IF NOT EXISTS observations (
  id TEXT PRIMARY KEY,
  assessment_id TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value_json TEXT NOT NULL,
  confidence REAL NOT NULL,
  source_tool TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  evidence_id TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_obs_asset_key ON observations(assessment_id, asset_id, key);
CREATE INDEX IF NOT EXISTS idx_obs_assessment ON observations(assessment_id);

-- 4. Tasks (evolved PackBoard with dependencies and fencing tokens)
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT NOT NULL,
  assessment_id TEXT NOT NULL,
  task_type TEXT NOT NULL DEFAULT 'lead_investigation',
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'normal',
  status TEXT NOT NULL,
  blocked_by_json TEXT NOT NULL DEFAULT '[]',
  fencing_token INTEGER NOT NULL DEFAULT 1,
  cas_version INTEGER NOT NULL DEFAULT 1,
  claim_json TEXT,
  result_json TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  -- Lead compatibility attributes
  fingerprint TEXT,
  location_json TEXT,
  classification_json TEXT,
  severity TEXT,
  confidence TEXT,
  smoke_score INTEGER NOT NULL DEFAULT 1,
  provenance TEXT,
  votes_json TEXT NOT NULL DEFAULT '[]',
  evidence_hashes_json TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(assessment_id, id),
  FOREIGN KEY(assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tasks_assessment ON tasks(assessment_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(assessment_id, status);
CREATE INDEX IF NOT EXISTS idx_tasks_fingerprint ON tasks(assessment_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_tasks_asset ON tasks(assessment_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_tasks_fencing ON tasks(id, fencing_token);

-- 5. Agents (agent registry & heartbeats)
CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT NOT NULL,
  assessment_id TEXT NOT NULL,
  capabilities_json TEXT NOT NULL,
  host_id TEXT NOT NULL,
  pid INTEGER NOT NULL,
  status TEXT NOT NULL,
  heartbeat_at INTEGER NOT NULL,
  registered_at INTEGER NOT NULL,
  PRIMARY KEY(assessment_id, agent_id),
  FOREIGN KEY(assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_agents_assessment ON agents(assessment_id);
CREATE INDEX IF NOT EXISTS idx_agents_heartbeat ON agents(assessment_id, heartbeat_at);

-- 6. Findings (6-state vulnerability lifecycle)
CREATE TABLE IF NOT EXISTS findings (
  id TEXT NOT NULL,
  assessment_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  state TEXT NOT NULL,
  cwe_json TEXT NOT NULL DEFAULT '[]',
  severity_json TEXT NOT NULL,
  confidence_json TEXT NOT NULL,
  location_json TEXT NOT NULL,
  evidence_ids_json TEXT NOT NULL DEFAULT '[]',
  remediation_json TEXT,
  cas_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(assessment_id, id),
  FOREIGN KEY(assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(assessment_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(assessment_id, state);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(assessment_id, asset_id);

-- 7. Transactional Outbox (reused from Phase 1)
CREATE TABLE IF NOT EXISTS transactional_outbox (
  outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  assessment_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  flushed INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_outbox_unflushed ON transactional_outbox (flushed) WHERE flushed = 0;
CREATE INDEX IF NOT EXISTS idx_outbox_event ON transactional_outbox (event_id);

-- 8. Analysis Runs (authoritative run identity and replay protection)
CREATE TABLE IF NOT EXISTS analysis_runs (
  run_id TEXT PRIMARY KEY,
  assessment_id TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  binary_sha256 TEXT NOT NULL,
  status TEXT NOT NULL,
  nonce TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  completed_at INTEGER,
  FOREIGN KEY(assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_assessment ON analysis_runs(assessment_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_status ON analysis_runs(status);

-- 9. Analysis Evidence Records (tamper-evident signed stage evidence storage)
CREATE TABLE IF NOT EXISTS analysis_evidence_records (
  evidence_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  assessment_id TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  claims_json TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  claims_digest TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  signature TEXT NOT NULL,
  key_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  consumed_at INTEGER,
  FOREIGN KEY(assessment_id) REFERENCES assessments(id) ON DELETE CASCADE,
  FOREIGN KEY(run_id) REFERENCES analysis_runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_analysis_evidence_run ON analysis_evidence_records(run_id);
CREATE INDEX IF NOT EXISTS idx_analysis_evidence_assessment ON analysis_evidence_records(assessment_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_analysis_evidence_stage ON analysis_evidence_records(stage);
`;

/**
 * Applies database schema and migrations idempotently to the SQLite database.
 */
export function applyBlackboardMigrations(db: DatabaseSync): void {
  db.exec("PRAGMA foreign_keys = OFF;");

  // Check if schema_migrations table exists
  const hasMigrations = db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
    )
    .get();

  if (!hasMigrations) {
    db.exec(BLACKBOARD_SCHEMA_DDL);
    db.prepare(
      "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
    ).run(BLACKBOARD_CURRENT_SCHEMA_VERSION, Date.now());
  } else {
    // Schema migrations table exists; check version
    const row = db
      .prepare("SELECT MAX(version) as max_v FROM schema_migrations")
      .get() as any;
    const currentV = row?.max_v ?? 0;

    if (currentV < BLACKBOARD_CURRENT_SCHEMA_VERSION) {
      db.exec(BLACKBOARD_SCHEMA_DDL);
      db.prepare(
        "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
      ).run(BLACKBOARD_CURRENT_SCHEMA_VERSION, Date.now());
    }
  }

  // Backward compatibility migration: If an older DB had 'leads' as a table instead of 'tasks',
  // migrate rows from 'leads' into 'tasks' and replace 'leads' with a view.
  const leadsMaster = db
    .prepare("SELECT type, sql FROM sqlite_master WHERE name='leads'")
    .get() as { type: string; sql: string } | undefined;

  if (leadsMaster?.type === "table") {
    // Ensure parent assessments exist for legacy leads before foreign key enforcement
    db.exec(`
      INSERT OR IGNORE INTO assessments (
        id, name, status, objective_json, authorization_json, metrics_json, created_at, updated_at
      )
      SELECT DISTINCT
        assessment_id,
        'Migrated Assessment ' || assessment_id,
        'active',
        '{}',
        '{}',
        '{}',
        COALESCE(MIN(created_at), 0),
        COALESCE(MAX(updated_at), 0)
      FROM leads;
    `);

    // Migrate existing leads into tasks
    db.exec(`
      INSERT OR IGNORE INTO tasks (
        id, assessment_id, task_type, title, description, asset_id, priority, status,
        blocked_by_json, fencing_token, cas_version, claim_json, result_json, metadata_json,
        fingerprint, location_json, classification_json, severity, confidence, smoke_score,
        provenance, votes_json, evidence_hashes_json, created_at, updated_at
      )
      SELECT
        id, assessment_id, 'lead_investigation', title, description, asset_id, 'normal', status,
        '[]', 1, cas_version, claim_json, NULL, '{}',
        fingerprint, location_json, classification_json, severity, confidence, smoke_score,
        provenance, votes_json, evidence_hashes_json, created_at, updated_at
      FROM leads;
    `);

    // Drop legacy table and replace with view
    db.exec("DROP TABLE leads;");
    createLeadsViewWithTriggers(db);
  } else if (!leadsMaster) {
    // Create view if leads does not exist
    createLeadsViewWithTriggers(db);
  }

  db.exec("PRAGMA foreign_keys = ON;");
}

function createLeadsViewWithTriggers(db: DatabaseSync): void {
  db.exec(`
    CREATE VIEW IF NOT EXISTS leads AS
    SELECT
      id, assessment_id, COALESCE(fingerprint, id) AS fingerprint, title, description,
      asset_id, COALESCE(location_json, '{}') AS location_json,
      COALESCE(classification_json, '{}') AS classification_json,
      COALESCE(severity, 'MEDIUM') AS severity, COALESCE(confidence, 'CONFIRMED') AS confidence,
      status, smoke_score, cas_version, COALESCE(provenance, 'source_scan') AS provenance,
      claim_json, votes_json, evidence_hashes_json, created_at, updated_at
    FROM tasks;

    CREATE TRIGGER IF NOT EXISTS trg_leads_insert INSTEAD OF INSERT ON leads
    BEGIN
      INSERT INTO tasks (
        id, assessment_id, task_type, title, description, asset_id, priority, status,
        blocked_by_json, fencing_token, cas_version, claim_json, result_json, metadata_json,
        fingerprint, location_json, classification_json, severity, confidence, smoke_score,
        provenance, votes_json, evidence_hashes_json, created_at, updated_at
      ) VALUES (
        NEW.id,
        NEW.assessment_id,
        'lead_investigation',
        NEW.title,
        NEW.description,
        NEW.asset_id,
        'normal',
        NEW.status,
        '[]',
        1,
        NEW.cas_version,
        NEW.claim_json,
        NULL,
        '{}',
        NEW.fingerprint,
        NEW.location_json,
        NEW.classification_json,
        NEW.severity,
        NEW.confidence,
        NEW.smoke_score,
        NEW.provenance,
        NEW.votes_json,
        NEW.evidence_hashes_json,
        NEW.created_at,
        NEW.updated_at
      );
    END;

    CREATE TRIGGER IF NOT EXISTS trg_leads_update INSTEAD OF UPDATE ON leads
    BEGIN
      UPDATE tasks SET
        title = NEW.title,
        description = NEW.description,
        status = NEW.status,
        smoke_score = NEW.smoke_score,
        cas_version = NEW.cas_version,
        claim_json = NEW.claim_json,
        votes_json = NEW.votes_json,
        evidence_hashes_json = NEW.evidence_hashes_json,
        updated_at = NEW.updated_at
      WHERE id = OLD.id AND assessment_id = OLD.assessment_id;
    END;

    CREATE TRIGGER IF NOT EXISTS trg_leads_delete INSTEAD OF DELETE ON leads
    BEGIN
      DELETE FROM tasks WHERE id = OLD.id AND assessment_id = OLD.assessment_id;
    END;
  `);
}
