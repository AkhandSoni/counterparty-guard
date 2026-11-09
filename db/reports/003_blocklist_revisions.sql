-- Migration: 003_blocklist_revisions.sql
-- Purpose: Authoritative active blocklist and immutable append-only revision ledger
-- Target Tables: active_blocklist, blocklist_revisions

PRAGMA foreign_keys = ON;

-- 1. Active blocklist table (queried directly during check decisions)
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

-- 2. Append-only blocklist revision ledger (strictly incremented revision numbers)
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
