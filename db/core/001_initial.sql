CREATE TABLE agents (
  id TEXT PRIMARY KEY,
  credential_hash TEXT NOT NULL UNIQUE,
  registration_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE evidence_snapshots (
  id TEXT PRIMARY KEY,
  network TEXT NOT NULL,
  source_mode TEXT NOT NULL,
  account_id TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  snapshot_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE checks (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  request_id TEXT NOT NULL,
  network TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  source_mode TEXT NOT NULL,
  action_json TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  nonce TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK (state IN ('claimed', 'complete', 'failed')),
  lease_owner TEXT,
  lease_until INTEGER NOT NULL,
  response_json TEXT,
  snapshot_id TEXT REFERENCES evidence_snapshots(id),
  expires_at INTEGER,
  invalidated_reason TEXT,
  created_at INTEGER NOT NULL,
  UNIQUE (agent_id, request_id)
);
CREATE TABLE permit_records (
  check_id TEXT PRIMARY KEY REFERENCES checks(id),
  network TEXT NOT NULL,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  nonce TEXT NOT NULL UNIQUE,
  permit_hash TEXT NOT NULL UNIQUE,
  permit_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE receiver_observations (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  network TEXT NOT NULL,
  source_mode TEXT NOT NULL,
  account_id TEXT NOT NULL,
  code_identity TEXT,
  snapshot_id TEXT NOT NULL REFERENCES evidence_snapshots(id),
  observed_at INTEGER NOT NULL
);
CREATE INDEX receiver_observations_lookup ON receiver_observations(agent_id, network, source_mode, account_id, observed_at);
CREATE TABLE policy_observations (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  network TEXT NOT NULL,
  revision TEXT NOT NULL,
  policy_json TEXT NOT NULL,
  observed_at INTEGER NOT NULL
);
CREATE TABLE executions (
  id TEXT PRIMARY KEY,
  check_id TEXT NOT NULL REFERENCES checks(id),
  agent_id TEXT NOT NULL REFERENCES agents(id),
  network TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  permit_hash TEXT NOT NULL UNIQUE,
  receiver_id TEXT NOT NULL,
  action_json TEXT NOT NULL,
  code_identity TEXT,
  stage TEXT NOT NULL CHECK (stage IN ('attempted', 'signed', 'submitted', 'pending', 'uncertain', 'succeeded', 'failed')),
  signed INTEGER NOT NULL DEFAULT 0 CHECK (signed IN (0, 1)),
  submitted INTEGER NOT NULL DEFAULT 0 CHECK (submitted IN (0, 1)),
  finalized INTEGER NOT NULL DEFAULT 0 CHECK (finalized IN (0, 1)),
  nonexecution_proven INTEGER NOT NULL DEFAULT 0 CHECK (nonexecution_proven IN (0, 1)),
  transaction_id TEXT,
  approval_reference TEXT,
  finalized_at INTEGER,
  updated_at INTEGER NOT NULL
);
CREATE TABLE execution_receipts (
  network TEXT NOT NULL,
  receipt_id TEXT NOT NULL,
  execution_id TEXT NOT NULL REFERENCES executions(id),
  receipt_hash TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  PRIMARY KEY (network, receipt_id)
);
CREATE INDEX executions_history ON executions(agent_id, network, receiver_id, stage, finalized);
