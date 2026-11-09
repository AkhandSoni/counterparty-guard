import { randomUUID } from 'node:crypto';
import type { ReportRecord } from '@counterparty-guard/shared';
import { describe, expect, it } from 'vitest';
import { createDatabase } from '../src/storage/db.js';
import { runMigrations } from '../src/storage/migrations.js';
import { ReportRepository } from '../src/storage/repository.js';

describe('SQLite Database & Migrations (db.test.ts)', () => {
  it('applies all 4 migrations successfully and records them in _migrations table', () => {
    const db = createDatabase({ path: ':memory:' });
    const applied = runMigrations(db);

    expect(applied).toEqual([
      '001_initial_reports.sql',
      '002_report_lifecycle.sql',
      '003_blocklist_revisions.sql',
      '004_dependence_groups.sql',
    ]);

    // Running again applies 0 new migrations (idempotent)
    const secondRun = runMigrations(db);
    expect(secondRun).toEqual([]);

    const migrationRows = db
      .prepare('SELECT name FROM _migrations ORDER BY id ASC')
      .all() as Array<{ name: string }>;
    expect(migrationRows.map((r) => r.name)).toEqual(applied);
  });

  it('enforces foreign key constraints and pragma', () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);

    // reports table references reporters(reporter_id)
    // Inserting report for nonexistent reporter fails with FOREIGN KEY constraint failed
    expect(() => {
      db.prepare(`
        INSERT INTO reports (
          report_id, network, accused_account_id, reporter_id, reporter_public_key,
          category, description, status, issued_at, expires_at, nonce, signature,
          created_at, updated_at
        ) VALUES (
          'rep-1', 'testnet', 'bad.testnet', 'nonexistent.testnet', 'ed25519:1111111111111111111111111111111111111111111',
          'drainer', 'desc test 12345', 'submitted', 1000, 2000, 'nonce-1', 'sig', 1000, 1000
        )
      `).run();
    }).toThrow(/FOREIGN KEY constraint failed/i);
  });

  it('enforces UNIQUE(reporter_id, nonce) replay protection at database level', () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db);

    repo.registerReporter({
      reporter_id: 'alice.testnet',
      public_key: 'ed25519:1111111111111111111111111111111111111111111',
      network: 'testnet',
    });

    const report1: ReportRecord = {
      report_id: randomUUID(),
      network: 'testnet',
      accused_account_id: 'scam.testnet',
      reporter_id: 'alice.testnet',
      reporter_public_key: 'ed25519:1111111111111111111111111111111111111111111',
      category: 'drainer',
      description: 'drainer test description min 10',
      transaction_references: ['ref-1'],
      evidence_content_hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
      contract_code_hash: null,
      status: 'submitted',
      issued_at: 1000,
      expires_at: 2000,
      nonce: 'fixed-nonce-1',
      signature: 'ed25519:sig',
      dependence_group_id: null,
      created_at: 1000,
    };

    repo.insertReport(report1);
    expect(repo.hasNonce('alice.testnet', 'fixed-nonce-1')).toBe(true);

    // Duplicate insert for same reporter and nonce must throw UNIQUE constraint failed
    const report2: ReportRecord = {
      ...report1,
      report_id: randomUUID(),
    };

    expect(() => repo.insertReport(report2)).toThrow(/UNIQUE constraint failed/i);

    // But another reporter can use the same nonce
    repo.registerReporter({
      reporter_id: 'bob.testnet',
      public_key: 'ed25519:2222222222222222222222222222222222222222222',
      network: 'testnet',
    });

    const reportBob: ReportRecord = {
      ...report1,
      report_id: randomUUID(),
      reporter_id: 'bob.testnet',
      reporter_public_key: 'ed25519:2222222222222222222222222222222222222222222',
    };

    expect(() => repo.insertReport(reportBob)).not.toThrow();
  });

  it('enforces CHECK(expires_at > issued_at) constraint', () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db);

    repo.registerReporter({
      reporter_id: 'alice.testnet',
      public_key: 'ed25519:1111111111111111111111111111111111111111111',
      network: 'testnet',
    });

    const invalidReport: ReportRecord = {
      report_id: randomUUID(),
      network: 'testnet',
      accused_account_id: 'scam.testnet',
      reporter_id: 'alice.testnet',
      reporter_public_key: 'ed25519:1111111111111111111111111111111111111111111',
      category: 'drainer',
      description: 'drainer test description min 10',
      transaction_references: [],
      evidence_content_hashes: [],
      contract_code_hash: null,
      status: 'submitted',
      issued_at: 2000,
      expires_at: 1000, // Invalid: expires_at < issued_at
      nonce: 'nonce-expiry',
      signature: 'ed25519:sig',
      dependence_group_id: null,
      created_at: 2000,
    };

    expect(() => repo.insertReport(invalidReport)).toThrow(/CHECK constraint failed/i);
  });

  it('supports full ReportRepository lifecycle operations and queries', () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db);

    // 1. Reporter upsert & query
    const reporter = repo.upsertReporter({
      reporter_id: 'auditor.testnet',
      public_key: 'ed25519:key1',
      network: 'testnet',
    });
    expect(reporter.reporter_id).toBe('auditor.testnet');
    expect(reporter.reputation_score).toBe(1.0);
    expect(reporter.total_reports).toBe(0);

    // 2. Report insert & status update
    const reportId = randomUUID();
    repo.insertReport({
      report_id: reportId,
      network: 'testnet',
      accused_account_id: 'hacker.testnet',
      reporter_id: 'auditor.testnet',
      reporter_public_key: 'ed25519:key1',
      category: 'drainer',
      description: 'Malicious drainer contract activity',
      transaction_references: ['tx-1', 'tx-2'],
      evidence_content_hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
      contract_code_hash: 'abc123codehash',
      status: 'submitted',
      issued_at: 1000,
      expires_at: 5000,
      nonce: 'nonce-auditor-1',
      signature: 'ed25519:sig1',
      dependence_group_id: null,
      created_at: 1000,
    });

    const fetchedReport = repo.getReport(reportId);
    expect(fetchedReport).not.toBeNull();
    expect(fetchedReport?.accused_account_id).toBe('hacker.testnet');
    expect(fetchedReport?.transaction_references).toEqual(['tx-1', 'tx-2']);
    expect(fetchedReport?.status).toBe('submitted');

    // Reporter total_reports incremented
    const updatedReporter = repo.getReporter('auditor.testnet');
    expect(updatedReporter?.total_reports).toBe(1);

    repo.updateReportStatus(reportId, 'references_verified');
    expect(repo.getReport(reportId)?.status).toBe('references_verified');

    // 3. Evidence references & verification logs
    const evId = repo.insertEvidenceReference({
      report_id: reportId,
      reference_type: 'transaction',
      reference_value: 'tx-1',
    });
    expect(evId).toBeDefined();

    const evRefs = repo.getEvidenceReferences(reportId);
    expect(evRefs.length).toBe(1);
    expect(evRefs[0].reference_value).toBe('tx-1');

    repo.insertVerificationLog({
      report_id: reportId,
      verifier_type: 'chain_rpc',
      check_name: 'tx_existence',
      passed: true,
      details: 'Transaction confirmed on NEAR block 123456',
    });

    // 4. Human Review & Active Blocklist
    const blockRes = repo.createActiveBlock({
      network: 'testnet',
      accused_account_id: 'hacker.testnet',
      contract_code_hash: 'abc123codehash',
      scope: 'both',
      reason: 'Confirmed drainer exploit after reviewer audit',
      reviewer_id: 'reviewer_alice',
      report_id: reportId,
    });

    expect(blockRes.entry_id).toBeDefined();
    expect(blockRes.blocklist_revision).toBe(1);

    const activeBlock = repo.getActiveBlock('testnet', 'hacker.testnet', 'abc123codehash');
    expect(activeBlock).not.toBeNull();
    expect(activeBlock?.is_active).toBe(1);
    expect(activeBlock?.reason).toContain('Confirmed drainer exploit');

    // Code hash lookup matches
    const blockByCode = repo.getActiveBlock('testnet', 'other_account.testnet', 'abc123codehash');
    expect(blockByCode).toBeNull();
    expect(blockByCode?.entry_id).toBeUndefined();

    // Log human review
    repo.insertReview({
      review_id: randomUUID(),
      report_id: reportId,
      reviewer_id: 'reviewer_alice',
      status: 'reviewed',
      decision: 'active_block',
      scope: 'both',
      reason: 'Confirmed drainer exploit after reviewer audit',
      blocklist_entry_id: blockRes.entry_id,
      blocklist_revision: blockRes.blocklist_revision,
      reviewed_at: Date.now(),
    });

    const reviews = repo.getReviewsByReport(reportId);
    expect(reviews.length).toBe(1);
    expect(reviews[0].decision).toBe('active_block');

    // 5. Revocation & Append-only Revisions
    const rev2 = repo.revokeActiveBlock(blockRes.entry_id, {
      reviewer_id: 'reviewer_bob',
      reason: 'False positive; reviewed developer clarification',
    });
    expect(rev2).toBe(2);
    expect(repo.getLatestBlocklistRevision()).toBe(2);

    // Active block is no longer returned
    const unblocked = repo.getActiveBlock('testnet', 'hacker.testnet', 'abc123codehash');
    expect(unblocked).toBeNull();

    const revisions = repo.getBlocklistRevisions(10);
    expect(revisions.length).toBe(2);
    expect(revisions[0].action).toBe('revoked');
    expect(revisions[1].action).toBe('added');

    // 6. Faucet exemptions check
    expect(repo.isFaucetExempted('testnet', 'faucet.testnet')).toBe(true);
    expect(repo.isFaucetExempted('testnet', 'testnet')).toBe(true);
    expect(repo.isFaucetExempted('sandbox', 'faucet.sandbox')).toBe(true);
    expect(repo.isFaucetExempted('testnet', 'unknown-user.testnet')).toBe(false);

    // 7. Dependence groups
    repo.upsertDependenceGroup({
      group_id: 'group-100',
      network: 'testnet',
      common_funder_id: 'funder.testnet',
      faucet_exempted: 0,
      effective_weight: 1.0,
      reporter_count: 5,
      clustering_reason: 'Funded by funder.testnet within 2 hops',
      created_at: 1000,
      updated_at: 1000,
    });

    const group = repo.getDependenceGroup('group-100');
    expect(group?.common_funder_id).toBe('funder.testnet');
    expect(group?.effective_weight).toBe(1.0);

    repo.addGroupMember('group-100', 'sybil1.testnet', 'reporter', 1);
    repo.addGroupMember('group-100', 'sybil2.testnet', 'reporter', 1);

    const members = repo.getGroupMembers('group-100');
    expect(members.length).toBe(2);
    expect(members.map((m) => m.account_id)).toContain('sybil1.testnet');
  });

  it('enforces scope constraints (account vs code_hash vs both) in getActiveBlock', () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db);

    // 1. Block with scope 'code_hash'
    repo.createActiveBlock({
      network: 'testnet',
      accused_account_id: 'contract-a.testnet',
      contract_code_hash: 'bad_hash_123',
      scope: 'code_hash',
      reason: 'Malicious bytecode drainer',
      reviewer_id: 'sec_reviewer.testnet',
    });

    // Query with matching account but different (or null) code hash must NOT be blocked
    expect(repo.getActiveBlock('testnet', 'contract-a.testnet', null)).toBeNull();
    expect(repo.getActiveBlock('testnet', 'contract-a.testnet', 'clean_hash_456')).toBeNull();

    // Query with matching code hash (even on another account) MUST be blocked
    const blockMatchByHash = repo.getActiveBlock(
      'testnet',
      'other-account.testnet',
      'bad_hash_123',
    );
    expect(blockMatchByHash).toBeNull();
    expect(blockMatchByHash?.contract_code_hash).toBeUndefined();

    // 2. Block with scope 'account'
    repo.createActiveBlock({
      network: 'testnet',
      accused_account_id: 'bad-operator.testnet',
      contract_code_hash: 'some_code_hash_789',
      scope: 'account',
      reason: 'Malicious operator address',
      reviewer_id: 'sec_reviewer.testnet',
    });

    // Query with matching account is blocked regardless of code hash
    expect(repo.getActiveBlock('testnet', 'bad-operator.testnet', null)).not.toBeNull();
    expect(repo.getActiveBlock('testnet', 'bad-operator.testnet', 'different_hash')).not.toBeNull();

    // Query on different account with same code hash must NOT be blocked
    expect(
      repo.getActiveBlock('testnet', 'clean-operator.testnet', 'some_code_hash_789'),
    ).toBeNull();
  });
});
