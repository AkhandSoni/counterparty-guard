-- Migration: 004_dependence_groups.sql
-- Purpose: Bounded graph clustering, Sybil discounting, and common faucet exemptions
-- Target Tables: dependence_groups, group_members, faucet_exemptions

PRAGMA foreign_keys = ON;

-- 1. Dependence groups for clustering correlated reports
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

-- 2. Group members linking accounts and reporters to clusters
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

-- 3. Configurable faucet exemptions (exempted from Sybil clustering)
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

-- Link reports table to dependence_groups
CREATE INDEX IF NOT EXISTS idx_reports_group ON reports(dependence_group_id);

-- Seed standard known testnet & sandbox faucets
INSERT OR IGNORE INTO faucet_exemptions (exemption_id, network, faucet_account_id, label, exemption_type, is_active, created_at, updated_at)
VALUES
    ('seed-testnet-faucet', 'testnet', 'faucet.testnet', 'Official NEAR Testnet Faucet', 'faucet', 1, 1700000000000, 1700000000000),
    ('seed-testnet-genesis', 'testnet', 'testnet', 'NEAR Testnet Genesis Account', 'system', 1, 1700000000000, 1700000000000),
    ('seed-testnet-v2-faucet', 'testnet', 'v2.near-faucet.testnet', 'Community Faucet v2', 'faucet', 1, 1700000000000, 1700000000000),
    ('seed-sandbox-faucet', 'sandbox', 'faucet.sandbox', 'Sandbox Local Faucet', 'faucet', 1, 1700000000000, 1700000000000);
