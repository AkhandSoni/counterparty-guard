import fs from 'node:fs';
import path from 'node:path';
import type { DatabaseSync } from './db.js';

export const EMBEDDED_MIGRATIONS: Array<{ name: string; sql: string }> = [
  {
    name: '001_initial_reports.sql',
    sql: `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS reporters (
    reporter_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    network TEXT NOT NULL CHECK(network IN ('testnet', 'mainnet', 'sandbox')),
    reputation_score REAL NOT NULL DEFAULT 1.0,
    total_reports INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reporters_network ON reporters(network);
CREATE INDEX IF NOT EXISTS idx_reporters_public_key ON reporters(public_key);

CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    network TEXT NOT NULL CHECK(network IN ('testnet', 'mainnet', 'sandbox')),
    accused_account_id TEXT NOT NULL,
    reporter_id TEXT NOT NULL REFERENCES reporters(reporter_id) ON DELETE RESTRICT,
    reporter_public_key TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN (
        'drainer', 'phishing', 'malicious_contract', 'impersonation',
        'prompt_injection_source', 'wash_trading', 'other'
    )),
    description TEXT NOT NULL,
    transaction_references TEXT NOT NULL DEFAULT '[]',
    evidence_content_hashes TEXT NOT NULL DEFAULT '[]',
    contract_code_hash TEXT,
    status TEXT NOT NULL DEFAULT 'submitted' CHECK(status IN (
        'submitted', 'references_verified', 'corroborated', 'reviewed',
        'rejected', 'withdrawn', 'expired'
    )),
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    nonce TEXT NOT NULL,
    signature TEXT NOT NULL,
    dependence_group_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    CONSTRAINT chk_report_expiry CHECK(expires_at > issued_at),
    CONSTRAINT uq_reporter_nonce UNIQUE(reporter_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_reports_accused ON reports(network, accused_account_id);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_reporter ON reports(reporter_id);
CREATE INDEX IF NOT EXISTS idx_reports_expires_at ON reports(expires_at);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at);
    `,
  },
  {
    name: '002_report_lifecycle.sql',
    sql: `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS evidence_references (
    evidence_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES reports(report_id) ON DELETE CASCADE,
    reference_type TEXT NOT NULL CHECK(reference_type IN ('transaction', 'receipt', 'content_hash', 'account')),
    reference_value TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0, 1)),
    verified_at INTEGER,
    verification_details TEXT,
    created_at INTEGER NOT NULL,
    CONSTRAINT uq_report_reference UNIQUE(report_id, reference_value)
);

CREATE INDEX IF NOT EXISTS idx_evidence_report ON evidence_references(report_id);
CREATE INDEX IF NOT EXISTS idx_evidence_ref_val ON evidence_references(reference_type, reference_value);

CREATE TABLE IF NOT EXISTS verification_logs (
    log_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES reports(report_id) ON DELETE CASCADE,
    verifier_type TEXT NOT NULL CHECK(verifier_type IN ('chain_rpc', 'content_verifier', 'automated_heuristics', 'reviewer')),
    check_name TEXT NOT NULL,
    passed INTEGER NOT NULL CHECK(passed IN (0, 1)),
    details TEXT,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verification_logs_report ON verification_logs(report_id);

CREATE TABLE IF NOT EXISTS report_reviews (
    review_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES reports(report_id) ON DELETE RESTRICT,
    reviewer_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('submitted', 'references_verified', 'corroborated', 'reviewed', 'rejected', 'withdrawn', 'expired')),
    decision TEXT NOT NULL CHECK(decision IN ('active_block', 'dismissed', 'corroborated', 'rejected')),
    scope TEXT NOT NULL DEFAULT 'account' CHECK(scope IN ('account', 'code_hash', 'both')),
    reason TEXT NOT NULL,
    blocklist_entry_id TEXT,
    blocklist_revision INTEGER NOT NULL DEFAULT 0,
    reviewed_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reviews_report ON report_reviews(report_id);
CREATE INDEX IF NOT EXISTS idx_reviews_reviewer ON report_reviews(reviewer_id);
CREATE INDEX IF NOT EXISTS idx_reviews_reviewed_at ON report_reviews(reviewed_at);
    `,
  },
  {
    name: '003_blocklist_revisions.sql',
    sql: `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS active_blocklist (
    entry_id TEXT PRIMARY KEY,
    network TEXT NOT NULL CHECK(network IN ('testnet', 'mainnet', 'sandbox')),
    accused_account_id TEXT NOT NULL,
    contract_code_hash TEXT,
    scope TEXT NOT NULL DEFAULT 'account' CHECK(scope IN ('account', 'code_hash', 'both')),
    reason TEXT NOT NULL,
    reviewer_id TEXT NOT NULL,
    report_id TEXT REFERENCES reports(report_id) ON DELETE SET NULL,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER,
    revoked_by TEXT,
    revocation_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_active_blocklist_lookup ON active_blocklist(network, accused_account_id, is_active);
CREATE INDEX IF NOT EXISTS idx_active_blocklist_code ON active_blocklist(network, contract_code_hash, is_active);
CREATE INDEX IF NOT EXISTS idx_active_blocklist_active ON active_blocklist(is_active);

CREATE TABLE IF NOT EXISTS blocklist_revisions (
    revision_number INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id TEXT NOT NULL REFERENCES active_blocklist(entry_id) ON DELETE RESTRICT,
    action TEXT NOT NULL CHECK(action IN ('added', 'updated', 'revoked', 'expired')),
    network TEXT NOT NULL CHECK(network IN ('testnet', 'mainnet', 'sandbox')),
    accused_account_id TEXT NOT NULL,
    contract_code_hash TEXT,
    scope TEXT NOT NULL CHECK(scope IN ('account', 'code_hash', 'both')),
    reviewer_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blocklist_revisions_entry ON blocklist_revisions(entry_id);
CREATE INDEX IF NOT EXISTS idx_blocklist_revisions_lookup ON blocklist_revisions(network, accused_account_id);
CREATE INDEX IF NOT EXISTS idx_blocklist_revisions_created ON blocklist_revisions(created_at);
    `,
  },
  {
    name: '004_dependence_groups.sql',
    sql: `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS dependence_groups (
    group_id TEXT PRIMARY KEY,
    network TEXT NOT NULL CHECK(network IN ('testnet', 'mainnet', 'sandbox')),
    common_funder_id TEXT,
    faucet_exempted INTEGER NOT NULL DEFAULT 0 CHECK(faucet_exempted IN (0, 1)),
    effective_weight REAL NOT NULL DEFAULT 1.0,
    reporter_count INTEGER NOT NULL DEFAULT 0,
    clustering_reason TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dependence_groups_network ON dependence_groups(network);
CREATE INDEX IF NOT EXISTS idx_dependence_groups_funder ON dependence_groups(common_funder_id);

CREATE TABLE IF NOT EXISTS group_members (
    membership_id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL REFERENCES dependence_groups(group_id) ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'reporter' CHECK(role IN ('reporter', 'funder', 'intermediary', 'accused')),
    hops_from_funder INTEGER NOT NULL DEFAULT 1,
    observed_at INTEGER NOT NULL,
    CONSTRAINT uq_group_member UNIQUE(group_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_account ON group_members(account_id);
CREATE INDEX IF NOT EXISTS idx_group_members_group ON group_members(group_id);

CREATE TABLE IF NOT EXISTS faucet_exemptions (
    exemption_id TEXT PRIMARY KEY,
    network TEXT NOT NULL CHECK(network IN ('testnet', 'mainnet', 'sandbox')),
    faucet_account_id TEXT NOT NULL,
    label TEXT NOT NULL,
    exemption_type TEXT NOT NULL DEFAULT 'faucet' CHECK(exemption_type IN ('faucet', 'bridge', 'exchange', 'system', 'other')),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    CONSTRAINT uq_faucet_exemption UNIQUE(network, faucet_account_id)
);

CREATE INDEX IF NOT EXISTS idx_faucet_exemptions_lookup ON faucet_exemptions(network, faucet_account_id, is_active);
CREATE INDEX IF NOT EXISTS idx_reports_group ON reports(dependence_group_id);

INSERT OR IGNORE INTO faucet_exemptions (exemption_id, network, faucet_account_id, label, exemption_type, is_active, created_at, updated_at)
VALUES
    ('seed-testnet-faucet', 'testnet', 'faucet.testnet', 'Official NEAR Testnet Faucet', 'faucet', 1, 1700000000000, 1700000000000),
    ('seed-testnet-genesis', 'testnet', 'testnet', 'NEAR Testnet Genesis Account', 'system', 1, 1700000000000, 1700000000000),
    ('seed-testnet-v2-faucet', 'testnet', 'v2.near-faucet.testnet', 'Community Faucet v2', 'faucet', 1, 1700000000000, 1700000000000),
    ('seed-sandbox-faucet', 'sandbox', 'faucet.sandbox', 'Sandbox Local Faucet', 'faucet', 1, 1700000000000, 1700000000000);
    `,
  },
];

export function runMigrations(db: DatabaseSync, migrationsDir?: string): string[] {
  db.exec(`
    CREATE TABLE IF NOT EXISTS _migrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      applied_at INTEGER NOT NULL
    );
  `);

  let migrationsToRun: Array<{ name: string; sql: string }> = [];

  if (migrationsDir && fs.existsSync(migrationsDir)) {
    const files = fs
      .readdirSync(migrationsDir)
      .filter((f) => f.endsWith('.sql'))
      .sort();
    migrationsToRun = files.map((f) => ({
      name: f,
      sql: fs.readFileSync(path.join(migrationsDir, f), 'utf-8'),
    }));
  } else {
    migrationsToRun = EMBEDDED_MIGRATIONS;
  }

  const appliedList: string[] = [];
  const checkStmt = db.prepare('SELECT 1 FROM _migrations WHERE name = ?');
  const recordStmt = db.prepare('INSERT INTO _migrations (name, applied_at) VALUES (?, ?)');

  for (const migration of migrationsToRun) {
    const alreadyApplied = checkStmt.get(migration.name);
    if (!alreadyApplied) {
      db.exec('BEGIN TRANSACTION;');
      try {
        db.exec(migration.sql);
        recordStmt.run(migration.name, Date.now());
        db.exec('COMMIT;');
        appliedList.push(migration.name);
      } catch (err) {
        db.exec('ROLLBACK;');
        throw new Error(`Failed to apply migration ${migration.name}: ${(err as Error).message}`);
      }
    }
  }

  return appliedList;
}
