export const PACKBOARD_DDL = `
CREATE TABLE IF NOT EXISTS leads (
  id TEXT PRIMARY KEY,
  assessment_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  location_json TEXT NOT NULL,
  classification_json TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  status TEXT NOT NULL,
  smoke_score INTEGER NOT NULL DEFAULT 1,
  cas_version INTEGER NOT NULL DEFAULT 1,
  provenance TEXT NOT NULL,
  claim_json TEXT,
  votes_json TEXT NOT NULL DEFAULT '[]',
  evidence_hashes_json TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_leads_assessment ON leads(assessment_id);
CREATE INDEX IF NOT EXISTS idx_leads_fingerprint ON leads(assessment_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(assessment_id, status);

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
`;

export interface SqliteLeadRow {
  readonly id: string;
  readonly assessment_id: string;
  readonly fingerprint: string;
  readonly title: string;
  readonly description: string;
  readonly asset_id: string;
  readonly location_json: string;
  readonly classification_json: string;
  readonly severity: string;
  readonly confidence: string;
  readonly status: string;
  readonly smoke_score: number;
  readonly cas_version: number;
  readonly provenance: string;
  readonly claim_json: string | null;
  readonly votes_json: string;
  readonly evidence_hashes_json: string;
  readonly created_at: number;
  readonly updated_at: number;
}

export interface SqliteOutboxRow {
  readonly outbox_id: number;
  readonly event_id: string;
  readonly event_type: string;
  readonly entity_type: string;
  readonly entity_id: string;
  readonly assessment_id: string;
  readonly payload_json: string;
  readonly created_at: number;
  readonly flushed: number;
}
