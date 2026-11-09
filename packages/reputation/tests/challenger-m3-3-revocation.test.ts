import { randomUUID } from 'node:crypto';
import type { ReportRecord } from '@counterparty-guard/shared';
import { describe, expect, it } from 'vitest';
import {
  LifecycleError,
  MemoryReportLifecycleRepository,
  ReportLifecycleEngine,
  ReviewerAuthorizationError,
  type ReviewerContext,
  evaluateBlockStatus,
} from '../src/lifecycle.js';
import { createDatabase } from '../src/storage/db.js';
import { runMigrations } from '../src/storage/migrations.js';
import { ReportRepository } from '../src/storage/repository.js';

describe('Adversarial Verification Suite: Revocation Remediation & Edge Cases (challenger_m3_3)', () => {
  const now = 1700000000000;

  const validReviewer: ReviewerContext = {
    reviewer_id: 'alice_lead_reviewer',
    role: 'reviewer',
    authenticated: true,
  };

  const adminReviewer: ReviewerContext = {
    reviewer_id: 'super_admin_reviewer',
    role: 'admin',
    authenticated: true,
  };

  const agentReviewer: ReviewerContext = {
    reviewer_id: 'autonomous_bot_agent',
    role: 'agent' as unknown as ReviewerContext['role'],
    authenticated: false,
  };

  const createSampleReport = (overrides: Partial<ReportRecord> = {}): ReportRecord => ({
    report_id: randomUUID(),
    network: 'testnet',
    accused_account_id: 'malicious-contract.testnet',
    reporter_id: 'reporter-1.testnet',
    reporter_public_key: 'ed25519:6EArrfeWY1oj5cENt3q2513dANDGfCJYg2f6w13q9qK8',
    category: 'drainer',
    description: 'Empirical test allegation for revocation testing',
    transaction_references: [],
    evidence_content_hashes: [],
    contract_code_hash: '11111111111111111111111111111111',
    status: 'submitted',
    issued_at: now - 3600_000,
    expires_at: now + 3600_000,
    nonce: randomUUID(),
    signature: 'fake-signature-for-lifecycle-testing',
    created_at: now - 3600_000,
    ...overrides,
  });

  // =========================================================================
  // 1. Core Remediation Verification: engine.revokeBlock against SQLite
  // =========================================================================
  describe('1. SQLite ReportRepository Remediation Verification', () => {
    it('engine.revokeBlock executes against SQLite without CHECK constraint errors, sets is_active = 0, and increments revision exactly by +1', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);
      const sqlEngine = new ReportLifecycleEngine(sqlRepo);

      const rep = createSampleReport({ accused_account_id: 'victim-merchant.testnet' });
      sqlRepo.registerReporter({
        reporter_id: rep.reporter_id,
        public_key: rep.reporter_public_key,
        network: rep.network,
      });
      sqlRepo.insertReport(rep);

      // Create active block via review
      const revOutcome = await sqlEngine.review(
        rep.report_id,
        {
          decision: 'active_block',
          scope: 'account',
          reason: 'Initial block after investigation',
        },
        validReviewer,
        now,
      );

      expect(revOutcome.blocklistRevision).toBe(1);
      const entryId = revOutcome.review.blocklist_entry_id as string;
      expect(entryId).toBeDefined();

      // Ensure block is currently active
      const activeBlockBefore = sqlRepo.getActiveBlock('testnet', 'victim-merchant.testnet', '11111111111111111111111111111111');
      expect(activeBlockBefore).not.toBeNull();
      if (!activeBlockBefore) {
        throw new Error('activeBlockBefore should exist');
      }

      // Verify evaluateBlockStatus returns true while active
      const statusBefore = evaluateBlockStatus(activeBlockBefore, 10, now);
      expect(statusBefore.isBlocked).toBe(true);

      // Revoke the block via engine
      const revokeOutcome = await sqlEngine.revokeBlock(
        entryId,
        'Merchant demonstrated legitimate credentials; unblocking immediately',
        adminReviewer,
        {
          network: 'testnet',
          accountId: 'victim-merchant.testnet',
          now: now + 60_000,
        },
      );

      // Exactly +1 revision increment: 1 -> 2
      expect(revokeOutcome.revision).toBe(2);
      expect(sqlRepo.getLatestBlocklistRevision()).toBe(2);

      // Active block must now be null
      const activeBlockAfter = sqlRepo.getActiveBlock('testnet', 'victim-merchant.testnet', '11111111111111111111111111111111');
      expect(activeBlockAfter).toBeNull();

      // Also verify code_hash query returns null
      const activeCodeBlock = sqlRepo.getActiveBlock(
        'testnet',
        'victim-merchant.testnet',
        '11111111111111111111111111111111',
      );
      expect(activeCodeBlock).toBeNull();

      // Direct SQL inspection: check active_blocklist table fields
      const blockRow = db
        .prepare('SELECT * FROM active_blocklist WHERE entry_id = ?')
        .get(entryId) as {
        entry_id: string;
        is_active: number;
        revoked_at: number;
        revoked_by: string;
        revocation_reason: string;
      };
      expect(blockRow).toBeDefined();
      expect(blockRow.is_active).toBe(0);
      expect(blockRow.revoked_at).toBe(now + 60_000);
      expect(blockRow.revoked_by).toBe(adminReviewer.reviewer_id);
      expect(blockRow.revocation_reason).toBe(
        'Merchant demonstrated legitimate credentials; unblocking immediately',
      );

      // Direct SQL inspection: check blocklist_revisions table has exactly 2 entries (no double revisions!)
      const revisions = db
        .prepare('SELECT * FROM blocklist_revisions ORDER BY revision_number ASC')
        .all() as Array<{
        revision_number: number;
        entry_id: string;
        action: string;
        network: string;
        accused_account_id: string;
        reviewer_id: string;
        reason: string;
        created_at: number;
      }>;

      expect(revisions.length).toBe(2);
      expect(revisions[0].revision_number).toBe(1);
      expect(revisions[0].action).toBe('added');
      expect(revisions[0].entry_id).toBe(entryId);

      expect(revisions[1].revision_number).toBe(2);
      expect(revisions[1].action).toBe('revoked');
      expect(revisions[1].entry_id).toBe(entryId);
      expect(revisions[1].reviewer_id).toBe(adminReviewer.reviewer_id);
      expect(revisions[1].created_at).toBe(now + 60_000);

      // Verify evaluateBlockStatus returns false when revoked
      const statusAfter = evaluateBlockStatus(null, 10, now + 60_000);
      expect(statusAfter.isBlocked).toBe(false);
    });

    it('appendBlocklistRevision correctly maps action "revoke" to "revoked" and "create" to "added"', () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);

      // First create active block entry so FK constraint passes
      const block = sqlRepo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'action-test.testnet',
        scope: 'account',
        reason: 'Testing direct action mapping',
        reviewer_id: 'alice',
      });
      expect(block.blocklist_revision).toBe(1);

      // Append with action = 'revoke'
      const revRev = sqlRepo.appendBlocklistRevision({
        action: 'revoke',
        entry_id: block.entry_id,
        network: 'testnet',
        target_type: 'account',
        account_id: 'action-test.testnet',
        code_hash: null,
        reviewer_id: 'alice',
        reason: 'Revoke test action',
        report_id: null,
        created_at: now,
      });
      expect(revRev).toBe(2);

      // Append with action = 'create'
      const createRev = sqlRepo.appendBlocklistRevision({
        action: 'create',
        entry_id: block.entry_id,
        network: 'testnet',
        target_type: 'account',
        account_id: 'action-test.testnet',
        code_hash: null,
        reviewer_id: 'alice',
        reason: 'Create test action',
        report_id: null,
        created_at: now,
      });
      expect(createRev).toBe(3);

      const rows = db
        .prepare(
          'SELECT revision_number, action FROM blocklist_revisions ORDER BY revision_number ASC',
        )
        .all() as Array<{ revision_number: number; action: string }>;

      expect(rows).toEqual([
        { revision_number: 1, action: 'added' },
        { revision_number: 2, action: 'revoked' },
        { revision_number: 3, action: 'added' },
      ]);
    });
  });

  // =========================================================================
  // 2. Strict Monotonicity Under Multiple Interleaved Operations
  // =========================================================================
  describe('2. Revision Ledger Strict Monotonicity (+1 Per Action)', () => {
    it('maintains strict sequential monotonicity across 5 block additions and 5 interleaved revocations', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);
      const sqlEngine = new ReportLifecycleEngine(sqlRepo);

      const entryIds: string[] = [];

      // Create 5 blocks
      for (let i = 1; i <= 5; i++) {
        const rep = createSampleReport({ accused_account_id: `target-${i}.testnet` });
        sqlRepo.registerReporter({
          reporter_id: rep.reporter_id,
          public_key: rep.reporter_public_key,
          network: rep.network,
        });
        sqlRepo.insertReport(rep);

        const rev = await sqlEngine.review(
          rep.report_id,
          { decision: 'active_block', scope: 'account', reason: `Block reason ${i}` },
          validReviewer,
          now + i * 1000,
        );
        expect(rev.blocklistRevision).toBe(i);
        expect(sqlRepo.getLatestBlocklistRevision()).toBe(i);
        entryIds.push(rev.review.blocklist_entry_id as string);
      }

      // Interleaved revocations: revoke 3, then 1, then 5, then 2, then 4
      const revocationOrder = [2, 0, 4, 1, 3]; // 0-indexed: target 3, 1, 5, 2, 4
      let expectedRev = 5;

      for (const idx of revocationOrder) {
        expectedRev++;
        const targetId = entryIds[idx];
        const res = await sqlEngine.revokeBlock(
          targetId,
          `Unblocking target ${idx + 1} with valid justification`,
          validReviewer,
          { now: now + expectedRev * 1000 },
        );
        expect(res.revision).toBe(expectedRev);
        expect(sqlRepo.getLatestBlocklistRevision()).toBe(expectedRev);

        // Verify that target is now unblocked
        const activeBlock = sqlRepo.getActiveBlock('testnet', `target-${idx + 1}.testnet`);
        expect(activeBlock).toBeNull();
      }

      expect(expectedRev).toBe(10);
      expect(sqlRepo.getLatestBlocklistRevision()).toBe(10);

      const allRows = db
        .prepare(
          'SELECT revision_number, action FROM blocklist_revisions ORDER BY revision_number ASC',
        )
        .all() as Array<{ revision_number: number; action: string }>;

      expect(allRows.length).toBe(10);
      for (let k = 0; k < 10; k++) {
        expect(allRows[k].revision_number).toBe(k + 1);
        expect(allRows[k].action).toBe(k < 5 ? 'added' : 'revoked');
      }
    });
  });

  // =========================================================================
  // 3. Edge Case: Revocation of Non-Existent Block Entry ID
  // =========================================================================
  describe('3. Edge Case: Non-Existent Block Entry ID Revocation', () => {
    it('throws Error with SQLite repository when entry_id does not exist, rolls back cleanly, and leaves revisions untouched', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);
      const sqlEngine = new ReportLifecycleEngine(sqlRepo);

      expect(sqlRepo.getLatestBlocklistRevision()).toBe(0);

      const fakeEntryId = 'non-existent-uuid-9999999';

      await expect(
        sqlEngine.revokeBlock(
          fakeEntryId,
          'Attempting to revoke a phantom block entry',
          validReviewer,
          { now },
        ),
      ).rejects.toThrow(`Active block entry not found: ${fakeEntryId}`);

      // Verify no revision was added and DB was rolled back
      expect(sqlRepo.getLatestBlocklistRevision()).toBe(0);

      const count = db.prepare('SELECT COUNT(*) as count FROM blocklist_revisions').get() as {
        count: number;
      };
      expect(count.count).toBe(0);
    });

    it('throws Error with MemoryReportLifecycleRepository when entry_id does not exist', async () => {
      const memRepo = new MemoryReportLifecycleRepository();
      const memEngine = new ReportLifecycleEngine(memRepo);

      const fakeEntryId = 'memory-phantom-uuid-1234';

      await expect(
        memEngine.revokeBlock(fakeEntryId, 'Revoking non-existent entry in memory', validReviewer, {
          now,
        }),
      ).rejects.toThrow(`Active block entry not found: ${fakeEntryId}`);

      expect(memRepo.getLatestBlocklistRevision()).toBe(0);
    });
  });

  // =========================================================================
  // 4. Edge Case: Reviewer Authority & Role Validation on Revocation
  // =========================================================================
  describe('4. Edge Case: Reviewer Authority Rejection on Revocation', () => {
    it('rejects revocation when reviewer is unauthenticated (agent context)', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);
      const sqlEngine = new ReportLifecycleEngine(sqlRepo);

      // Create a legitimate block
      const block = sqlRepo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'auth-test-target.testnet',
        scope: 'account',
        reason: 'Block for authority testing',
        reviewer_id: 'alice',
      });
      expect(sqlRepo.getLatestBlocklistRevision()).toBe(1);

      // Attempt revoke with unauthenticated agent
      await expect(
        sqlEngine.revokeBlock(
          block.entry_id,
          'Unauthorized agent attempting unblock',
          agentReviewer,
        ),
      ).rejects.toThrow(ReviewerAuthorizationError);

      // Verify block is STILL active
      expect(sqlRepo.getLatestBlocklistRevision()).toBe(1);
      const active = sqlRepo.getActiveBlock('testnet', 'auth-test-target.testnet');
      expect(active).not.toBeNull();
      expect(active?.is_active).toBe(1);
    });

    it('rejects revocation when reviewer context is null or undefined', async () => {
      const memRepo = new MemoryReportLifecycleRepository();
      const memEngine = new ReportLifecycleEngine(memRepo);

      await expect(
        memEngine.revokeBlock(
          'any-id',
          'Unblocking without context',
          null as unknown as ReviewerContext,
        ),
      ).rejects.toThrow(ReviewerAuthorizationError);

      await expect(
        memEngine.revokeBlock(
          'any-id',
          'Unblocking with undefined context',
          undefined as unknown as ReviewerContext,
        ),
      ).rejects.toThrow(ReviewerAuthorizationError);
    });

    it('rejects revocation when reviewer role is unauthorized (reporter, user, observer, operator)', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);
      const sqlEngine = new ReportLifecycleEngine(sqlRepo);

      const block = sqlRepo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'unauth-role.testnet',
        scope: 'account',
        reason: 'Block for role check',
        reviewer_id: 'alice',
      });

      const invalidRoles = ['user', 'reporter', 'observer', 'operator', 'auditor', 'agent'];

      for (const role of invalidRoles) {
        const fakeCtx = {
          reviewer_id: `actor_with_${role}`,
          role: role as unknown as ReviewerContext['role'],
          authenticated: true,
        };

        await expect(
          sqlEngine.revokeBlock(block.entry_id, 'Role bypass attempt with valid reason', fakeCtx),
        ).rejects.toThrow(ReviewerAuthorizationError);
      }

      // Block remains active
      expect(sqlRepo.getLatestBlocklistRevision()).toBe(1);
      expect(sqlRepo.getActiveBlock('testnet', 'unauth-role.testnet')).not.toBeNull();
    });

    it('rejects revocation when reason is shorter than 5 characters or empty', async () => {
      const memRepo = new MemoryReportLifecycleRepository();
      const memEngine = new ReportLifecycleEngine(memRepo);

      const shortReasons = ['', '   ', 'ok', 'undo', '1234'];

      for (const reason of shortReasons) {
        await expect(memEngine.revokeBlock('entry-1', reason, validReviewer)).rejects.toThrow(
          LifecycleError,
        );
      }
    });
  });

  // =========================================================================
  // 5. Edge Case: Double Revocation of Already Revoked Block
  // =========================================================================
  describe('5. Edge Case: Double Revocation of Already Revoked Block', () => {
    it('empirically examines behavior of double revocation on real SQLite repository', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);
      const sqlEngine = new ReportLifecycleEngine(sqlRepo);

      const rep = createSampleReport({ accused_account_id: 'double-revoke.testnet' });
      sqlRepo.registerReporter({
        reporter_id: rep.reporter_id,
        public_key: rep.reporter_public_key,
        network: rep.network,
      });
      sqlRepo.insertReport(rep);

      const rev1 = await sqlEngine.review(
        rep.report_id,
        { decision: 'active_block', scope: 'account', reason: 'Initial active block' },
        validReviewer,
        now,
      );
      const entryId = rev1.review.blocklist_entry_id as string;
      expect(rev1.blocklistRevision).toBe(1);

      // First revocation:
      const firstRevoke = await sqlEngine.revokeBlock(
        entryId,
        'First legitimate unblock by reviewer',
        validReviewer,
        { now: now + 1000 },
      );
      expect(firstRevoke.revision).toBe(2);
      expect(sqlRepo.getActiveBlock('testnet', 'double-revoke.testnet')).toBeNull();

      // Second revocation of the same entry:
      // In SQLite active_blocklist, the row still exists with is_active = 0.
      // Calling revokeBlock again executes against the existing row.
      const secondRevoke = await sqlEngine.revokeBlock(
        entryId,
        'Second unblock call on already revoked block entry',
        validReviewer,
        { now: now + 2000 },
      );

      // Verifies outcome:
      // The revision increments monotonically to 3 without crashing or constraint violation.
      expect(secondRevoke.revision).toBe(3);
      expect(sqlRepo.getLatestBlocklistRevision()).toBe(3);

      // Most importantly, the target remains unblocked:
      expect(sqlRepo.getActiveBlock('testnet', 'double-revoke.testnet')).toBeNull();

      // Row in active_blocklist remains is_active = 0
      const row = db
        .prepare(
          'SELECT is_active, revoked_at, revocation_reason FROM active_blocklist WHERE entry_id = ?',
        )
        .get(entryId) as { is_active: number; revoked_at: number; revocation_reason: string };
      expect(row.is_active).toBe(0);
      expect(row.revoked_at).toBe(now + 2000);
      expect(row.revocation_reason).toBe('Second unblock call on already revoked block entry');
    });

    it('empirically examines behavior of double revocation on MemoryReportLifecycleRepository', async () => {
      const memRepo = new MemoryReportLifecycleRepository();
      const memEngine = new ReportLifecycleEngine(memRepo);

      const rep = createSampleReport({ accused_account_id: 'double-revoke-mem.testnet' });
      memRepo.reports.set(rep.report_id, rep);

      const rev = await memEngine.review(
        rep.report_id,
        { decision: 'active_block', scope: 'account', reason: 'Block in memory' },
        validReviewer,
        now,
      );
      const entryId = rev.review.blocklist_entry_id as string;
      expect(rev.blocklistRevision).toBe(1);

      // First revocation
      const r1 = await memEngine.revokeBlock(entryId, 'Unblock memory block 1', validReviewer, {
        now: now + 1000,
      });
      expect(r1.revision).toBe(2);
      expect(memRepo.getActiveBlocklistEntry('testnet', 'double-revoke-mem.testnet')).toBeNull();

      // Second revocation
      const r2 = await memEngine.revokeBlock(entryId, 'Unblock memory block 2', validReviewer, {
        now: now + 2000,
      });
      expect(r2.revision).toBe(3);
      expect(memRepo.getLatestBlocklistRevision()).toBe(3);
      expect(memRepo.getActiveBlocklistEntry('testnet', 'double-revoke-mem.testnet')).toBeNull();

      // Parity between memory and SQLite is 100% consistent!
    });
  });

  // =========================================================================
  // 6. Adversarial Attack Scenarios: SQL Injection & Scope Matrix
  // =========================================================================
  describe('6. Adversarial Scope Matrix & Injection Attacks', () => {
    it('handles scope=code_hash block and revocation cleanly', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);
      const sqlEngine = new ReportLifecycleEngine(sqlRepo);

      const codeHash = '22222222222222222222222222222222';
      const rep = createSampleReport({
        accused_account_id: 'code-hash-target.testnet',
        contract_code_hash: codeHash,
      });
      sqlRepo.registerReporter({
        reporter_id: rep.reporter_id,
        public_key: rep.reporter_public_key,
        network: rep.network,
      });
      sqlRepo.insertReport(rep);

      const revOutcome = await sqlEngine.review(
        rep.report_id,
        { decision: 'active_block', scope: 'code_hash', reason: 'Malicious bytecode detected' },
        validReviewer,
        now,
      );

      const entryId = revOutcome.review.blocklist_entry_id as string;
      const activeByCode = sqlRepo.getActiveBlock('testnet', 'code-hash-target.testnet', codeHash);
      expect(activeByCode).not.toBeNull();
      expect(activeByCode?.contract_code_hash).toBe(codeHash);

      // Revoke code_hash block
      const unblockRes = await sqlEngine.revokeBlock(
        entryId,
        'Bytecode re-analyzed and cleared of malicious heuristics',
        adminReviewer,
      );
      expect(unblockRes.revision).toBe(2);

      const activeAfter = sqlRepo.getActiveBlock('testnet', 'code-hash-target.testnet', codeHash);
      expect(activeAfter).toBeNull();
    });

    it('safely handles SQL injection attempts in revocation reason and entryId', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);
      const sqlEngine = new ReportLifecycleEngine(sqlRepo);

      const rep = createSampleReport({ accused_account_id: 'sqli-victim.testnet' });
      sqlRepo.registerReporter({
        reporter_id: rep.reporter_id,
        public_key: rep.reporter_public_key,
        network: rep.network,
      });
      sqlRepo.insertReport(rep);

      const revOutcome = await sqlEngine.review(
        rep.report_id,
        { decision: 'active_block', scope: 'account', reason: 'Normal block' },
        validReviewer,
        now,
      );
      const entryId = revOutcome.review.blocklist_entry_id as string;

      // 1. Attack via entryId: SQL injection string
      const sqliEntryId = `${entryId}' OR '1'='1`;
      await expect(
        sqlEngine.revokeBlock(sqliEntryId, 'Valid justification string', validReviewer),
      ).rejects.toThrow(`Active block entry not found: ${sqliEntryId}`);

      // 2. Attack via reason containing SQL injection payload
      const sqliReasons = [
        "'; DROP TABLE active_blocklist; --",
        "'; DROP TABLE blocklist_revisions; --",
        "' OR '1'='1' UNION SELECT 1, 2, 3; --",
        'test"; UPDATE active_blocklist SET is_active = 1; --',
      ];

      for (let i = 0; i < sqliReasons.length; i++) {
        const sqliReason = sqliReasons[i];
        // Create fresh block for each iteration
        const subRep = createSampleReport({ accused_account_id: `sqli-target-${i}.testnet` });
        sqlRepo.registerReporter({
          reporter_id: subRep.reporter_id,
          public_key: subRep.reporter_public_key,
          network: subRep.network,
        });
        sqlRepo.insertReport(subRep);
        const subReview = await sqlEngine.review(
          subRep.report_id,
          { decision: 'active_block', scope: 'account', reason: 'Prep block' },
          validReviewer,
          now,
        );

        const subEntryId = subReview.review.blocklist_entry_id as string;
        const res = await sqlEngine.revokeBlock(subEntryId, sqliReason, validReviewer);
        expect(res.revision).toBeGreaterThan(0);

        // Verify active_blocklist and blocklist_revisions tables still exist and are not corrupted
        const checkActive = db
          .prepare('SELECT is_active, revocation_reason FROM active_blocklist WHERE entry_id = ?')
          .get(subEntryId) as { is_active: number; revocation_reason: string };
        expect(checkActive.is_active).toBe(0);
        expect(checkActive.revocation_reason).toBe(sqliReason);
      }
    });

    it('revoking an expired block sets is_active = 0 and records audit revision cleanly', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);
      const sqlEngine = new ReportLifecycleEngine(sqlRepo);

      // Create block with past expires_at
      const block = sqlRepo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'expired-block.testnet',
        scope: 'account',
        reason: 'Temporary block with expiry',
        reviewer_id: 'alice',
        expires_at: now - 1000, // already expired
      });
      expect(block.blocklist_revision).toBe(1);

      // Even before manual revocation, getActiveBlock evaluates as null due to expiry
      expect(sqlRepo.getActiveBlock('testnet', 'expired-block.testnet')).toBeNull();

      // Explicit revocation by reviewer updates audit trail
      const revokeOutcome = await sqlEngine.revokeBlock(
        block.entry_id,
        'Explicit manual revocation of expired entry for audit hygiene',
        validReviewer,
        { now },
      );
      expect(revokeOutcome.revision).toBe(2);

      const row = db
        .prepare('SELECT is_active, revoked_by FROM active_blocklist WHERE entry_id = ?')
        .get(block.entry_id) as { is_active: number; revoked_by: string };
      expect(row.is_active).toBe(0);
      expect(row.revoked_by).toBe(validReviewer.reviewer_id);
    });
  });
});
