-- Migration: 001_initial_reports.sql
-- Purpose: Reporters registration and signed allegations storage
-- Target Tables: reporters, reports

PRAGMA foreign_keys = ON;

-- 1. Reporters table
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

-- 2. Signed Reports table
CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    network TEXT NOT NULL CHECK(network IN ('testnet', 'mainnet', 'sandbox')),
    accused_account_id TEXT NOT NULL,
    reporter_id TEXT NOT NULL REFERENCES reporters(reporter_id) ON DELETE RESTRICT,
    reporter_public_key TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN (
        'drainer',
        'phishing',
        'malicious_contract',
        'impersonation',
        'prompt_injection_source',
        'wash_trading',
        'other'
    )),
    description TEXT NOT NULL,
    transaction_references TEXT NOT NULL DEFAULT '[]',
    evidence_content_hashes TEXT NOT NULL DEFAULT '[]',
    contract_code_hash TEXT,
    status TEXT NOT NULL DEFAULT 'submitted' CHECK(status IN (
        'submitted',
        'references_verified',
        'corroborated',
        'reviewed',
        'rejected',
        'withdrawn',
        'expired'
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
