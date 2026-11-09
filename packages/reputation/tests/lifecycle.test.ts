import { randomUUID } from 'node:crypto';
import type { ReportRecord, ReviewReportRequest } from '@counterparty-guard/shared';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  type IReferenceVerifier,
  InvalidStateTransitionError,
  MemoryReportLifecycleRepository,
  ReportExpiredError,
  ReportLifecycleEngine,
  ReviewerAuthorizationError,
  type ReviewerContext,
  assertValidTransition,
  canTransition,
  evaluateBlockStatus,
} from '../src/lifecycle.js';
import { createDatabase } from '../src/storage/db.js';
import { runMigrations } from '../src/storage/migrations.js';
import { ReportRepository } from '../src/storage/repository.js';

describe('Report Lifecycle State Machine & Reviewer Authority (lifecycle.test.ts)', () => {
  let repo: MemoryReportLifecycleRepository;
  let engine: ReportLifecycleEngine;
  const now = 1700000000000;

  const validReviewer: ReviewerContext = {
    reviewer_id: 'alice_reviewer',
    role: 'reviewer',
    authenticated: true,
  };

  const agentContext: ReviewerContext = {
    reviewer_id: 'automated_agent_1',
    role: 'reviewer',
    authenticated: false, // Agent tokens are not authenticated human reviewers
  };

  const createSampleReport = (overrides: Partial<ReportRecord> = {}): ReportRecord => ({
    report_id: randomUUID(),
    network: 'testnet',
    accused_account_id: 'drainer-target.testnet',
    reporter_id: 'reporter-1.testnet',
    reporter_public_key: 'ed25519:1111111111111111111111111111111111111111111',
    category: 'drainer',
    description: 'Confirmed drainer exploit attacking vault permits.',
    transaction_references: ['tx-hash-100', 'tx-hash-200'],
    evidence_content_hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    contract_code_hash: 'abc123codehash',
    status: 'submitted',
    issued_at: now - 100_000,
    expires_at: now + 500_000,
    nonce: `nonce-${Math.random()}`,
    signature: 'ed25519:sig',
    dependence_group_id: null,
    created_at: now - 100_000,
    ...overrides,
  });

  beforeEach(() => {
    repo = new MemoryReportLifecycleRepository();
    engine = new ReportLifecycleEngine(repo);
  });

  describe('1. Transition Matrix & canTransition', () => {
    it('allows valid transitions from submitted', () => {
      expect(canTransition('submitted', 'references_verified')).toBe(true);
      expect(canTransition('submitted', 'corroborated')).toBe(true);
      expect(canTransition('submitted', 'reviewed')).toBe(true);
      expect(canTransition('submitted', 'rejected')).toBe(true);
      expect(canTransition('submitted', 'expired')).toBe(true);
      expect(canTransition('submitted', 'withdrawn')).toBe(true);
    });

    it('allows valid transitions from references_verified', () => {
      expect(canTransition('references_verified', 'corroborated')).toBe(true);
      expect(canTransition('references_verified', 'reviewed')).toBe(true);
      expect(canTransition('references_verified', 'rejected')).toBe(true);
      expect(canTransition('references_verified', 'submitted')).toBe(false);
    });

    it('disallows transitions from terminal states', () => {
      expect(canTransition('rejected', 'submitted')).toBe(false);
      expect(canTransition('rejected', 'reviewed')).toBe(false);
      expect(canTransition('expired', 'corroborated')).toBe(false);
      expect(canTransition('withdrawn', 'references_verified')).toBe(false);
    });

    it('throws InvalidStateTransitionError when assertValidTransition is violated', () => {
      expect(() => assertValidTransition('rejected', 'reviewed', 'rep-1')).toThrow(
        InvalidStateTransitionError,
      );
    });
  });

  describe('2. Reference Verification', () => {
    it('transitions to references_verified when all transaction references exist and involve accused account', async () => {
      const report = createSampleReport();
      repo.reports.set(report.report_id, report);

      const mockVerifier: IReferenceVerifier = {
        async verifyTransaction(_network, _txHash) {
          return {
            exists: true,
            receiverId: 'drainer-target.testnet',
            signerId: 'victim.testnet',
            blockHeight: 12345,
            timestamp: now - 50_000,
          };
        },
        async getAccountCodeHash(_network, _accountId) {
          return 'abc123codehash';
        },
      };

      const outcome = await engine.verifyReferences(report.report_id, mockVerifier, now);
      expect(outcome.status).toBe('references_verified');
      expect(outcome.result.verified).toBe(true);
      expect(outcome.result.matched_references).toBe(2);
      expect(outcome.result.code_hash_matched).toBe(true);

      expect(repo.getReportById(report.report_id)?.status).toBe('references_verified');
      expect(repo.verificationLogs.length).toBe(1);
    });

    it('transitions to rejected when transaction does not involve accused account', async () => {
      const report = createSampleReport();
      repo.reports.set(report.report_id, report);

      const mockVerifier: IReferenceVerifier = {
        async verifyTransaction(_network, _txHash) {
          return {
            exists: true,
            receiverId: 'unrelated.testnet', // mismatch
            signerId: 'another.testnet',
          };
        },
      };

      const outcome = await engine.verifyReferences(report.report_id, mockVerifier, now);
      expect(outcome.status).toBe('rejected');
      expect(outcome.result.verified).toBe(false);
      expect(repo.getReportById(report.report_id)?.status).toBe('rejected');
    });

    it('transitions to rejected when referenced transaction does not exist', async () => {
      const report = createSampleReport();
      repo.reports.set(report.report_id, report);

      const mockVerifier: IReferenceVerifier = {
        async verifyTransaction(_network, _txHash) {
          return { exists: false };
        },
      };

      const outcome = await engine.verifyReferences(report.report_id, mockVerifier, now);
      expect(outcome.status).toBe('rejected');
      expect(outcome.result.verified).toBe(false);
    });

    it('throws ReportExpiredError if report has expired', async () => {
      const expiredReport = createSampleReport({ expires_at: now - 1000 });
      repo.reports.set(expiredReport.report_id, expiredReport);

      const mockVerifier: IReferenceVerifier = {
        async verifyTransaction() {
          return { exists: true };
        },
      };

      await expect(
        engine.verifyReferences(expiredReport.report_id, mockVerifier, now),
      ).rejects.toThrow(ReportExpiredError);
      expect(repo.getReportById(expiredReport.report_id)?.status).toBe('expired');
    });
  });

  describe('3. Corroboration & Sybil Resistance', () => {
    it('corroborates when independent clusters concur', async () => {
      const mainReport = createSampleReport({
        status: 'references_verified',
        dependence_group_id: 'cluster_A',
      });
      const concurringReport = createSampleReport({
        status: 'references_verified',
        reporter_id: 'independent_reporter_2',
        dependence_group_id: 'cluster_B',
      });

      repo.reports.set(mainReport.report_id, mainReport);
      repo.reports.set(concurringReport.report_id, concurringReport);

      const outcome = await engine.corroborate(mainReport.report_id, {
        candidateReports: [mainReport, concurringReport],
        now,
      });

      expect(outcome.status).toBe('corroborated');
      expect(outcome.result.corroborated).toBe(true);
      expect(outcome.result.independent_clusters_count).toBe(1);
    });

    it('Sybil Defense: reports in the SAME dependence group DO NOT corroborate', async () => {
      const mainReport = createSampleReport({
        status: 'references_verified',
        dependence_group_id: 'sybil_cluster_99',
      });
      const colludingReport1 = createSampleReport({
        status: 'references_verified',
        reporter_id: 'sybil_bot_2',
        dependence_group_id: 'sybil_cluster_99', // same group
      });
      const colludingReport2 = createSampleReport({
        status: 'references_verified',
        reporter_id: 'sybil_bot_3',
        dependence_group_id: 'sybil_cluster_99', // same group
      });

      repo.reports.set(mainReport.report_id, mainReport);
      repo.reports.set(colludingReport1.report_id, colludingReport1);
      repo.reports.set(colludingReport2.report_id, colludingReport2);

      const outcome = await engine.corroborate(mainReport.report_id, {
        candidateReports: [mainReport, colludingReport1, colludingReport2],
        now,
      });

      // Still references_verified, NOT corroborated
      expect(outcome.status).toBe('references_verified');
      expect(outcome.result.corroborated).toBe(false);
      expect(outcome.result.independent_clusters_count).toBe(0);
    });

    it('corroborates via external intelligence signals even without secondary reports', async () => {
      const mainReport = createSampleReport({ status: 'references_verified' });
      repo.reports.set(mainReport.report_id, mainReport);

      const outcome = await engine.corroborate(mainReport.report_id, {
        externalIntelSignals: ['KNOWN_DRAINER_BYTECODE_MATCH_SHA256'],
        now,
      });

      expect(outcome.status).toBe('corroborated');
      expect(outcome.result.corroborated).toBe(true);
    });
  });

  describe('4. Reviewer Authority Invariant & Blocklist Revisions', () => {
    it('Reviewer Authority Invariant: raw report count (even 10,000) CANNOT trigger a block', () => {
      // 10,000 raw unreviewed reports
      const status10k = evaluateBlockStatus(null, 10_000, now);
      expect(status10k.isBlocked).toBe(false);

      // Even with 100,000 reports
      const status100k = evaluateBlockStatus(null, 100_000, now);
      expect(status100k.isBlocked).toBe(false);
    });

    it('rejects review attempts without authenticated reviewer authority (e.g. agent token)', async () => {
      const report = createSampleReport();
      repo.reports.set(report.report_id, report);

      const reviewReq: ReviewReportRequest = {
        decision: 'active_block',
        scope: 'account',
        reason: 'Attempted block by automated agent',
      };

      await expect(engine.review(report.report_id, reviewReq, agentContext, now)).rejects.toThrow(
        ReviewerAuthorizationError,
      );
    });

    it('creates active block entry and appends to blocklist revisions upon authenticated reviewer decision', async () => {
      const report = createSampleReport({ status: 'corroborated' });
      repo.reports.set(report.report_id, report);

      const reviewReq: ReviewReportRequest = {
        decision: 'active_block',
        scope: 'account',
        reason: 'Malicious drainer verified through human forensic review.',
        block_expires_at: now + 86400_000, // 24 hours
      };

      const reviewOutcome = await engine.review(report.report_id, reviewReq, validReviewer, now);

      expect(reviewOutcome.newStatus).toBe('reviewed');
      expect(reviewOutcome.blocklistRevision).toBe(1);
      expect(reviewOutcome.review.decision).toBe('active_block');

      // Verify active block entry in repository
      const blockEntry = repo.getActiveBlocklistEntry(
        'testnet',
        'drainer-target.testnet',
        'abc123codehash',
      );
      expect(blockEntry).not.toBeNull();
      expect(blockEntry?.status).toBe('active');
      expect(blockEntry?.reason).toContain('Malicious drainer verified');

      // Now evaluateBlockStatus produces isBlocked: true
      const evaluation = evaluateBlockStatus(blockEntry, 1, now);
      expect(evaluation.isBlocked).toBe(true);
      expect(evaluation.reason).toContain('Malicious drainer verified');

      // Check revision ledger
      expect(repo.revisions.length).toBe(1);
      expect(repo.revisions[0].revision).toBe(1);
      expect(repo.revisions[0].action).toBe('create');
      expect(repo.revisions[0].reviewer_id).toBe('alice_reviewer');
    });

    it('authenticated block revocation appends new revision and removes block status', async () => {
      const report = createSampleReport();
      repo.reports.set(report.report_id, report);

      // First create active block (rev 1)
      const reviewRes = await engine.review(
        report.report_id,
        {
          decision: 'active_block',
          scope: 'account',
          reason: 'Initial block',
        },
        validReviewer,
        now,
      );
      expect(reviewRes.blocklistRevision).toBe(1);
      const entryId = String(reviewRes.review.blocklist_entry_id);

      // Now reviewer revokes block (rev 2)
      const revokeOutcome = await engine.revokeBlock(
        entryId,
        'Account clarified as legitimate after developer audit',
        validReviewer,
        { now: now + 5000 },
      );

      expect(revokeOutcome.revision).toBe(2);
      expect(repo.revisions.length).toBe(2);
      expect(repo.revisions[1].action).toBe('revoke');
      expect(repo.revisions[1].revision).toBe(2);

      // Block is no longer active
      const entry = repo.getActiveBlocklistEntry('testnet', 'drainer-target.testnet');
      expect(entry).toBeNull();

      const evaluation = evaluateBlockStatus(entry, 0, now + 5000);
      expect(evaluation.isBlocked).toBe(false);
    });

    it('evaluateBlockStatus automatically unblocks when block TTL expires', () => {
      const expiredBlock = {
        is_active: 1,
        reason: 'Temporary 1-hour block',
        expires_at: now - 1000, // expired 1s ago
      };

      const result = evaluateBlockStatus(expiredBlock, 5, now);
      expect(result.isBlocked).toBe(false);
    });

    it('dismissal decision sets status to reviewed without creating active block', async () => {
      const report = createSampleReport();
      repo.reports.set(report.report_id, report);

      const reviewOutcome = await engine.review(
        report.report_id,
        {
          decision: 'dismissed',
          scope: 'account',
          reason: 'Allegation unsubstantiated upon investigation',
        },
        validReviewer,
        now,
      );

      expect(reviewOutcome.newStatus).toBe('reviewed');
      expect(reviewOutcome.review.blocklist_entry_id).toBeNull();
      expect(repo.blocklist.size).toBe(0);
      expect(repo.revisions.length).toBe(0);
    });

    it('throws ReportExpiredError when reviewing an expired report', async () => {
      const expiredReport = createSampleReport({ expires_at: now - 1000 });
      repo.reports.set(expiredReport.report_id, expiredReport);

      await expect(
        engine.review(
          expiredReport.report_id,
          {
            decision: 'active_block',
            scope: 'account',
            reason: 'Attempting review on expired report',
          },
          validReviewer,
          now,
        ),
      ).rejects.toThrow(ReportExpiredError);

      expect(repo.getReportById(expiredReport.report_id)?.status).toBe('expired');
    });
  });

  describe('5. Integration with SQLite Database and Repository', () => {
    it('executes full review and blocklist lifecycle on real SQLite database', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);

      // 1. Insert report
      const rep = createSampleReport();
      sqlRepo.registerReporter({
        reporter_id: rep.reporter_id,
        public_key: rep.reporter_public_key,
        network: rep.network,
      });
      sqlRepo.insertReport(rep);

      // 2. Verify references via engine using sqlRepo
      const sqlEngine = new ReportLifecycleEngine(sqlRepo);
      const verifier: IReferenceVerifier = {
        async verifyTransaction() {
          return { exists: true, receiverId: rep.accused_account_id };
        },
      };

      const verOutcome = await sqlEngine.verifyReferences(rep.report_id, verifier, now);
      expect(verOutcome.status).toBe('references_verified');

      // 3. Human review and active block
      const revOutcome = await sqlEngine.review(
        rep.report_id,
        {
          decision: 'active_block',
          scope: 'account',
          reason: 'Reviewed in SQLite integration test',
        },
        validReviewer,
        now,
      );

      expect(revOutcome.newStatus).toBe('reviewed');
      expect(revOutcome.blocklistRevision).toBe(1);

      // Verify in SQLite
      const activeBlock = sqlRepo.getActiveBlock('testnet', rep.accused_account_id);
      expect(activeBlock).not.toBeNull();
      expect(activeBlock?.is_active).toBe(1);

      // 4. Revocation via engine
      const blockEntryId = activeBlock ? activeBlock.entry_id : '';
      const revOutcome2 = await sqlEngine.revokeBlock(
        blockEntryId,
        'Unblocking after review',
        validReviewer,
      );
      expect(revOutcome2.revision).toBe(2);
      expect(sqlRepo.getLatestBlocklistRevision()).toBe(2);

      const unblocked = sqlRepo.getActiveBlock('testnet', rep.accused_account_id);
      expect(unblocked).toBeNull();
    });

    it('engine.revokeBlock executed against real SQLite ReportRepository succeeds, updates is_active = 0, and increments blocklist revision monotonically without SQLite constraint errors', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);
      const sqlEngine = new ReportLifecycleEngine(sqlRepo);

      const rep = createSampleReport({ accused_account_id: 'sqlite-revoke-target.testnet' });
      sqlRepo.registerReporter({
        reporter_id: rep.reporter_id,
        public_key: rep.reporter_public_key,
        network: rep.network,
      });
      sqlRepo.insertReport(rep);

      const reviewOutcome = await sqlEngine.review(
        rep.report_id,
        {
          decision: 'active_block',
          scope: 'account',
          reason: 'Initial test block for revocation regression',
        },
        validReviewer,
        now,
      );
      expect(reviewOutcome.blocklistRevision).toBe(1);
      const entryId = String(reviewOutcome.review.blocklist_entry_id);

      // Verify active block exists
      const activeBlock = sqlRepo.getActiveBlock('testnet', 'sqlite-revoke-target.testnet');
      expect(activeBlock).not.toBeNull();
      expect(activeBlock?.is_active).toBe(1);

      // Revoke via engine
      const revokeOutcome = await sqlEngine.revokeBlock(
        entryId,
        'Revocation rationale after comprehensive audit',
        validReviewer,
        {
          network: 'testnet',
          accountId: 'sqlite-revoke-target.testnet',
          now: now + 10000,
        },
      );

      // Verify revision monotonically incremented to 2
      expect(revokeOutcome.revision).toBe(2);
      expect(sqlRepo.getLatestBlocklistRevision()).toBe(2);

      // Verify block is now inactive (is_active = 0)
      const afterRevokeActive = sqlRepo.getActiveBlock('testnet', 'sqlite-revoke-target.testnet');
      expect(afterRevokeActive).toBeNull();

      // Directly verify row in active_blocklist table has is_active = 0
      const rawBlockRow = db
        .prepare(
          'SELECT is_active, revoked_at, revoked_by, revocation_reason FROM active_blocklist WHERE entry_id = ?',
        )
        .get(entryId) as {
        is_active: number;
        revoked_at: number;
        revoked_by: string;
        revocation_reason: string;
      };
      expect(rawBlockRow.is_active).toBe(0);
      expect(rawBlockRow.revoked_by).toBe(validReviewer.reviewer_id);
      expect(rawBlockRow.revocation_reason).toBe('Revocation rationale after comprehensive audit');

      // Verify blocklist_revisions table has action = 'revoked'
      const revisions = db
        .prepare(
          'SELECT revision_number, action, scope, reviewer_id FROM blocklist_revisions ORDER BY revision_number ASC',
        )
        .all() as Array<{
        revision_number: number;
        action: string;
        scope: string;
        reviewer_id: string;
      }>;
      expect(revisions).toHaveLength(2);
      expect(revisions[0].action).toBe('added');
      expect(revisions[1].action).toBe('revoked');
      expect(revisions[1].revision_number).toBe(2);
    });
  });
});
