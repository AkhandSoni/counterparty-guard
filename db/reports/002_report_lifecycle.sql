-- Migration: 002_report_lifecycle.sql
-- Purpose: Evidence normalization, verification logs, and human review records
-- Target Tables: evidence_references, verification_logs, report_reviews

PRAGMA foreign_keys = ON;

-- 1. Normalized evidence references for deduplication and audit
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

-- 2. Audit logs for automated and on-chain reference verification
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

-- 3. Human reviewer actions and moderation decisions
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
