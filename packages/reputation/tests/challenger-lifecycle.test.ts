import { randomUUID } from 'node:crypto';
import type { ReportRecord, ReviewReportRequest } from '@counterparty-guard/shared';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  type ActiveBlocklistEntry,
  LifecycleError,
  MemoryReportLifecycleRepository,
  ReportLifecycleEngine,
  ReviewerAuthorizationError,
  type ReviewerContext,
  assertReviewerAuthority,
  evaluateBlockStatus,
} from '../src/lifecycle.js';
import { createDatabase } from '../src/storage/db.js';
import { runMigrations } from '../src/storage/migrations.js';
import { ReportRepository } from '../src/storage/repository.js';

describe('Empirical Adversarial Challenge Suite: Lifecycle & Reviewer Authority (challenger_m3_2)', () => {
  let memoryRepo: MemoryReportLifecycleRepository;
  let engine: ReportLifecycleEngine;
  const now = 1700000000000;

  const validReviewer: ReviewerContext = {
    reviewer_id: 'alice_reviewer_human',
    role: 'reviewer',
    authenticated: true,
  };

  const validAdmin: ReviewerContext = {
    reviewer_id: 'bob_admin_human',
    role: 'admin',
    authenticated: true,
  };

  const createReport = (overrides: Partial<ReportRecord> = {}): ReportRecord => ({
    report_id: randomUUID(),
    network: 'testnet',
    accused_account_id: 'innocent-merchant.testnet',
    reporter_id: `sybil-reporter-${randomUUID().slice(0, 8)}.testnet`,
    reporter_public_key: 'ed25519:1111111111111111111111111111111111111111111',
    category: 'drainer',
    description: 'Adversarial false-report flood test allegation.',
    transaction_references: ['tx-hash-ref-1'],
    evidence_content_hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    contract_code_hash: 'code_hash_abc123',
    status: 'submitted',
    issued_at: now - 50_000,
    expires_at: now + 500_000,
    nonce: `nonce-${randomUUID()}`,
    signature: 'ed25519:mock_sig',
    dependence_group_id: null,
    created_at: now - 50_000,
    ...overrides,
  });

  beforeEach(() => {
    memoryRepo = new MemoryReportLifecycleRepository();
    engine = new ReportLifecycleEngine(memoryRepo);
  });

  // ==========================================================================
  // CHALLENGE DIMENSION 1: S4 Coordinated False-Report Flood Attack
  // ==========================================================================
  describe('Dimension 1: Coordinated False-Report Flood Attack (Scenario S4)', () => {
    it('S4 Invariant: 1,000 raw unreviewed reports NEVER trigger a hard block (evaluateBlockStatus isBlocked=false)', () => {
      // Attacker coordinates 1,000 raw unreviewed reports
      const floodCount = 1_000;
      const result = evaluateBlockStatus(null, floodCount, now);

      expect(result.isBlocked).toBe(false);
      expect(result.reason).toBeUndefined();
    });

    it('S4 Invariant: Scaling report volume to 100,000 reports preserves isBlocked=false', () => {
      const scaleCounts = [0, 1, 5, 50, 500, 1_000, 10_000, 50_000, 100_000, 1_000_000];
      for (const count of scaleCounts) {
        const res = evaluateBlockStatus(null, count, now);
        expect(res.isBlocked).toBe(false);
      }
    });

    it('S4 SQLite Persistence: 1,000 reports inserted into real SQLite database produce zero active blocks', () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);

      const targetAccount = 'victim-merchant.testnet';
      const floodSize = 1_000;

      // Attacker submits 1,000 reports to the SQLite storage
      for (let i = 0; i < floodSize; i++) {
        const reporterId = `bot-${i}.testnet`;
        sqlRepo.registerReporter({
          reporter_id: reporterId,
          public_key: 'pk_mock',
          network: 'testnet',
        });
        sqlRepo.insertReport(
          createReport({
            accused_account_id: targetAccount,
            reporter_id: reporterId,
            nonce: `flood-nonce-${i}`,
          }),
        );
      }

      // 1. Verify 1,000 reports were persisted
      const storedReports = sqlRepo.findReportsByAccused('testnet', targetAccount);
      expect(storedReports.length).toBe(floodSize);

      // 2. Invariant: active_blocklist lookup MUST return null
      const activeBlock = sqlRepo.getActiveBlock('testnet', targetAccount);
      expect(activeBlock).toBeNull();

      // 3. Block status evaluation returns isBlocked=false despite 1,000 raw reports
      const status = evaluateBlockStatus(activeBlock, storedReports.length, now);
      expect(status.isBlocked).toBe(false);
    });

    it('S4 Invariant: Reports in references_verified status still CANNOT trigger active block without human review', async () => {
      const report = createReport({ status: 'references_verified' });
      memoryRepo.reports.set(report.report_id, report);

      // Verify that references_verified status alone does not generate an active block
      const activeBlock = memoryRepo.getActiveBlocklistEntry('testnet', report.accused_account_id);
      expect(activeBlock).toBeNull();

      const evalResult = evaluateBlockStatus(activeBlock, 1, now);
      expect(evalResult.isBlocked).toBe(false);
    });

    it('S4 Invariant: Reports in corroborated status still CANNOT trigger active block without human review', async () => {
      const report = createReport({ status: 'corroborated' });
      memoryRepo.reports.set(report.report_id, report);

      const activeBlock = memoryRepo.getActiveBlocklistEntry('testnet', report.accused_account_id);
      expect(activeBlock).toBeNull();

      const evalResult = evaluateBlockStatus(activeBlock, 10, now);
      expect(evalResult.isBlocked).toBe(false);
    });

    it('TTL Expiration: Active block automatically unblocks after expires_at timestamp even if reports remain', () => {
      const expiredBlock: ActiveBlocklistEntry = {
        entry_id: randomUUID(),
        network: 'testnet',
        target_type: 'account',
        account_id: 'merchant.testnet',
        code_hash: null,
        origin_report_id: null,
        origin_review_id: 'rev-1',
        reviewer_id: 'alice',
        reason: 'Temporary precautionary block',
        status: 'active',
        created_at: now - 3600_000,
        expires_at: now - 1000, // expired 1s ago
        revoked_at: null,
        revocation_reason: null,
        revocation_reviewer_id: null,
      };

      // Invariant: evaluateBlockStatus returns false when expires_at <= now
      const result = evaluateBlockStatus(expiredBlock, 500, now);
      expect(result.isBlocked).toBe(false);
    });

    it('Revoked Block: Revoked active block returns isBlocked: false even if reports remain', () => {
      const revokedBlock: ActiveBlocklistEntry = {
        entry_id: randomUUID(),
        network: 'testnet',
        target_type: 'account',
        account_id: 'merchant.testnet',
        code_hash: null,
        origin_report_id: null,
        origin_review_id: 'rev-1',
        reviewer_id: 'alice',
        reason: 'Past block',
        status: 'revoked',
        created_at: now - 3600_000,
        expires_at: null,
        revoked_at: now - 1000,
        revocation_reason: 'Account cleared',
        revocation_reviewer_id: 'bob',
      };

      const result = evaluateBlockStatus(revokedBlock, 1_000, now);
      expect(result.isBlocked).toBe(false);
    });
  });

  // ==========================================================================
  // CHALLENGE DIMENSION 2: Unauthenticated Reviewer Calls & Authority Checks
  // ==========================================================================
  describe('Dimension 2: Reviewer Authorization Invariant', () => {
    it('throws ReviewerAuthorizationError when review called with authenticated=false (agent context)', async () => {
      const report = createReport();
      memoryRepo.reports.set(report.report_id, report);

      const agentContext: ReviewerContext = {
        reviewer_id: 'autonomous-agent-007',
        role: 'reviewer',
        authenticated: false,
      };

      const req: ReviewReportRequest = {
        decision: 'active_block',
        scope: 'account',
        reason: 'Agent automated decision',
      };

      await expect(engine.review(report.report_id, req, agentContext, now)).rejects.toThrow(
        ReviewerAuthorizationError,
      );
    });

    it('throws ReviewerAuthorizationError when reviewer context is null or undefined', async () => {
      const report = createReport();
      memoryRepo.reports.set(report.report_id, report);

      const req: ReviewReportRequest = {
        decision: 'active_block',
        scope: 'account',
        reason: 'Attempted block without context',
      };

      const nullContext = null as unknown as ReviewerContext;
      const undefinedContext = undefined as unknown as ReviewerContext;

      await expect(engine.review(report.report_id, req, nullContext, now)).rejects.toThrow(
        ReviewerAuthorizationError,
      );
      await expect(engine.review(report.report_id, req, undefinedContext, now)).rejects.toThrow(
        ReviewerAuthorizationError,
      );
    });

    it('throws ReviewerAuthorizationError for unauthorized roles (user, reporter, observer, agent)', () => {
      const unauthorizedRoles = ['user', 'reporter', 'observer', 'agent', 'operator'];

      for (const role of unauthorizedRoles) {
        const fakeContext = {
          reviewer_id: 'unauthorized_actor',
          role: role as unknown as ReviewerContext['role'],
          authenticated: true,
        };

        expect(() => assertReviewerAuthority(fakeContext)).toThrow(ReviewerAuthorizationError);
      }
    });

    it('allows valid human reviewers with role=reviewer or role=admin', () => {
      expect(() => assertReviewerAuthority(validReviewer)).not.toThrow();
      expect(() => assertReviewerAuthority(validAdmin)).not.toThrow();
    });

    it('throws ReviewerAuthorizationError when unauthenticated context attempts revokeBlock', async () => {
      const unauthContext: ReviewerContext = {
        reviewer_id: 'agent_attacker',
        role: 'reviewer',
        authenticated: false,
      };

      await expect(
        engine.revokeBlock('entry-123', 'Attacker attempting unblock', unauthContext),
      ).rejects.toThrow(ReviewerAuthorizationError);
    });

    it('throws LifecycleError when revokeBlock reason is under 5 characters', async () => {
      await expect(engine.revokeBlock('entry-123', 'bad', validReviewer)).rejects.toThrow(
        LifecycleError,
      );

      await expect(engine.revokeBlock('entry-123', '', validReviewer)).rejects.toThrow(
        LifecycleError,
      );
    });

    it('throws InvalidStateTransitionError when reviewing report in terminal status (rejected, withdrawn, expired)', async () => {
      const terminalStatuses: ('rejected' | 'withdrawn' | 'expired')[] = [
        'rejected',
        'withdrawn',
        'expired',
      ];

      for (const status of terminalStatuses) {
        const termReport = createReport({ status });
        memoryRepo.reports.set(termReport.report_id, termReport);

        await expect(
          engine.review(
            termReport.report_id,
            { decision: 'active_block', scope: 'account', reason: 'Attempt review terminal' },
            validReviewer,
            now,
          ),
        ).rejects.toThrow(LifecycleError);
      }
    });
  });

  // ==========================================================================
  // CHALLENGE DIMENSION 3: Sybil Group Corroboration Defense
  // ==========================================================================
  describe('Dimension 3: Sybil Group Corroboration Defense', () => {
    it('Sybil Defense: 100 reports in the SAME dependence_group_id cannot corroborate each other', async () => {
      const sybilGroupId = 'sybil_botnet_cluster_42';
      const mainReport = createReport({
        status: 'references_verified',
        dependence_group_id: sybilGroupId,
      });
      memoryRepo.reports.set(mainReport.report_id, mainReport);

      // Create 100 colluding reports with same group id
      const candidates: ReportRecord[] = [mainReport];
      for (let i = 0; i < 100; i++) {
        const colludingReport = createReport({
          status: 'references_verified',
          reporter_id: `sybil_bot_${i}.testnet`,
          dependence_group_id: sybilGroupId,
        });
        memoryRepo.reports.set(colludingReport.report_id, colludingReport);
        candidates.push(colludingReport);
      }

      // Execute corroboration
      const outcome = await engine.corroborate(mainReport.report_id, {
        candidateReports: candidates,
        now,
      });

      // Assert corroboration fails
      expect(outcome.status).toBe('references_verified'); // does NOT transition to 'corroborated'
      expect(outcome.result.corroborated).toBe(false);
      expect(outcome.result.independent_clusters_count).toBe(0);
      expect(outcome.result.concurring_reports_count).toBe(100);
      expect(outcome.result.notes).toBe('Insufficient independent concurrence');
    });

    it('Self-Corroboration Attack: Same reporter with multiple reports (null dependence group) cannot corroborate self', async () => {
      const sameReporterId = 'solo_sybil_puppeteer.testnet';
      const reportA = createReport({
        status: 'references_verified',
        reporter_id: sameReporterId,
        dependence_group_id: null,
      });
      const reportB = createReport({
        status: 'references_verified',
        reporter_id: sameReporterId,
        dependence_group_id: null,
      });
      const reportC = createReport({
        status: 'references_verified',
        reporter_id: sameReporterId,
        dependence_group_id: null,
      });

      memoryRepo.reports.set(reportA.report_id, reportA);
      memoryRepo.reports.set(reportB.report_id, reportB);
      memoryRepo.reports.set(reportC.report_id, reportC);

      const outcome = await engine.corroborate(reportA.report_id, {
        candidateReports: [reportA, reportB, reportC],
        now,
      });

      expect(outcome.status).toBe('references_verified');
      expect(outcome.result.corroborated).toBe(false);
      expect(outcome.result.independent_clusters_count).toBe(0);
    });

    it('Unverified reports from independent clusters CANNOT corroborate (must be references_verified or reviewed)', async () => {
      const mainReport = createReport({
        status: 'references_verified',
        dependence_group_id: 'cluster_alpha',
      });
      // Independent cluster, but unverified 'submitted' state
      const unverifiedReport = createReport({
        status: 'submitted',
        reporter_id: 'independent_reporter.testnet',
        dependence_group_id: 'cluster_beta',
      });

      memoryRepo.reports.set(mainReport.report_id, mainReport);
      memoryRepo.reports.set(unverifiedReport.report_id, unverifiedReport);

      const outcome = await engine.corroborate(mainReport.report_id, {
        candidateReports: [mainReport, unverifiedReport],
        now,
      });

      expect(outcome.status).toBe('references_verified');
      expect(outcome.result.corroborated).toBe(false);
      expect(outcome.result.independent_clusters_count).toBe(0);
    });

    it('Independent cluster with references_verified successfully corroborates', async () => {
      const mainReport = createReport({
        status: 'references_verified',
        dependence_group_id: 'sybil_botnet',
      });
      const legitimateReport = createReport({
        status: 'references_verified',
        reporter_id: 'independent_security_auditor.testnet',
        dependence_group_id: 'auditor_cluster_legit',
      });

      memoryRepo.reports.set(mainReport.report_id, mainReport);
      memoryRepo.reports.set(legitimateReport.report_id, legitimateReport);

      const outcome = await engine.corroborate(mainReport.report_id, {
        candidateReports: [mainReport, legitimateReport],
        now,
      });

      expect(outcome.status).toBe('corroborated');
      expect(outcome.result.corroborated).toBe(true);
      expect(outcome.result.independent_clusters_count).toBe(1);
    });

    it('External intelligence signal alone is sufficient for corroboration', async () => {
      const mainReport = createReport({
        status: 'references_verified',
        dependence_group_id: 'sybil_botnet',
      });
      memoryRepo.reports.set(mainReport.report_id, mainReport);

      const outcome = await engine.corroborate(mainReport.report_id, {
        candidateReports: [mainReport],
        externalIntelSignals: ['CHAINALYSIS_KNOWN_MALICIOUS_TAG'],
        now,
      });

      expect(outcome.status).toBe('corroborated');
      expect(outcome.result.corroborated).toBe(true);
      expect(outcome.result.external_evidence_signals).toContain('CHAINALYSIS_KNOWN_MALICIOUS_TAG');
    });
  });

  // ==========================================================================
  // CHALLENGE DIMENSION 4: Monotonic Incrementation of Blocklist Revision Ledger
  // ==========================================================================
  describe('Dimension 4: Monotonic Incrementation of blocklist_revision Ledger', () => {
    it('Monotonicity Invariant: Multiple block and revoke actions produce strictly increasing revisions (rev_i = rev_{i-1} + 1)', async () => {
      expect(memoryRepo.getLatestBlocklistRevision()).toBe(0);

      // Target 1
      const rep1 = createReport({ accused_account_id: 'drainer-1.testnet' });
      memoryRepo.reports.set(rep1.report_id, rep1);

      const res1 = await engine.review(
        rep1.report_id,
        { decision: 'active_block', scope: 'account', reason: 'Block 1' },
        validReviewer,
        now,
      );
      expect(res1.blocklistRevision).toBe(1);
      expect(memoryRepo.getLatestBlocklistRevision()).toBe(1);

      // Target 2
      const rep2 = createReport({ accused_account_id: 'drainer-2.testnet' });
      memoryRepo.reports.set(rep2.report_id, rep2);

      const res2 = await engine.review(
        rep2.report_id,
        { decision: 'active_block', scope: 'account', reason: 'Block 2' },
        validReviewer,
        now + 1000,
      );
      expect(res2.blocklistRevision).toBe(2);
      expect(memoryRepo.getLatestBlocklistRevision()).toBe(2);

      // Revoke Target 1
      const revoke1 = await engine.revokeBlock(
        String(res1.review.blocklist_entry_id),
        'Cleared false accusation',
        validReviewer,
        { now: now + 2000 },
      );
      expect(revoke1.revision).toBe(3);
      expect(memoryRepo.getLatestBlocklistRevision()).toBe(3);

      // Target 3
      const rep3 = createReport({ accused_account_id: 'drainer-3.testnet' });
      memoryRepo.reports.set(rep3.report_id, rep3);

      const res3 = await engine.review(
        rep3.report_id,
        { decision: 'active_block', scope: 'account', reason: 'Block 3' },
        validReviewer,
        now + 3000,
      );
      expect(res3.blocklistRevision).toBe(4);
      expect(memoryRepo.getLatestBlocklistRevision()).toBe(4);

      // Assert full revision list is strictly monotonic
      const revisions = memoryRepo.getBlocklistRevisions();
      expect(revisions.map((r) => r.revision)).toEqual([1, 2, 3, 4]);
    });

    it('Dismissal / Rejection decisions do NOT increment blocklist revision', async () => {
      const rep = createReport();
      memoryRepo.reports.set(rep.report_id, rep);

      expect(memoryRepo.getLatestBlocklistRevision()).toBe(0);

      const dismissRes = await engine.review(
        rep.report_id,
        { decision: 'dismissed', scope: 'account', reason: 'Dismissed unproven claim' },
        validReviewer,
        now,
      );

      expect(dismissRes.newStatus).toBe('reviewed');
      expect(dismissRes.blocklistRevision).toBe(0);
      expect(memoryRepo.getLatestBlocklistRevision()).toBe(0);
      expect(memoryRepo.revisions.length).toBe(0);
    });

    it('SQLite Monotonicity: Direct repository calls enforce strictly monotonic blocklist revisions', () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);

      expect(sqlRepo.getLatestBlocklistRevision()).toBe(0);

      // 1. Create Block A
      const b1 = sqlRepo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'target-a.testnet',
        scope: 'account',
        reason: 'Block A',
        reviewer_id: 'alice',
      });
      expect(b1.blocklist_revision).toBe(1);
      expect(sqlRepo.getLatestBlocklistRevision()).toBe(1);

      // 2. Create Block B
      const b2 = sqlRepo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'target-b.testnet',
        scope: 'account',
        reason: 'Block B',
        reviewer_id: 'alice',
      });
      expect(b2.blocklist_revision).toBe(2);
      expect(sqlRepo.getLatestBlocklistRevision()).toBe(2);

      // 3. Revoke Block A
      const rev1 = sqlRepo.revokeActiveBlock(b1.entry_id, {
        reviewer_id: 'alice',
        reason: 'Unblocking A',
      });
      expect(rev1).toBe(3);
      expect(sqlRepo.getLatestBlocklistRevision()).toBe(3);

      // 4. Revoke Block B
      const rev2 = sqlRepo.revokeActiveBlock(b2.entry_id, {
        reviewer_id: 'alice',
        reason: 'Unblocking B',
      });
      expect(rev2).toBe(4);
      expect(sqlRepo.getLatestBlocklistRevision()).toBe(4);
    });

    /**
     * EMPIRICAL DEFECT RESOLUTION:
     * When engine.revokeBlock is executed against the persistent SQLite ReportRepository,
     * it succeeds without SQLite CHECK constraint failures, atomically updates is_active = 0,
     * and increments blocklist_revisions monotonically.
     */
    it('verifies fix: engine.revokeBlock succeeds without SQLite CHECK constraint when called with ReportRepository', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const sqlRepo = new ReportRepository(db, () => now);
      const sqlEngine = new ReportLifecycleEngine(sqlRepo);

      // Setup report and active block via engine
      const rep = createReport({ accused_account_id: 'defect-target.testnet' });
      sqlRepo.registerReporter({
        reporter_id: rep.reporter_id,
        public_key: rep.reporter_public_key,
        network: rep.network,
      });
      sqlRepo.insertReport(rep);

      const reviewOutcome = await sqlEngine.review(
        rep.report_id,
        { decision: 'active_block', scope: 'account', reason: 'Initial test block' },
        validReviewer,
        now,
      );
      expect(reviewOutcome.blocklistRevision).toBe(1);
      const entryId = String(reviewOutcome.review.blocklist_entry_id);

      // Attempt revokeBlock through the lifecycle engine on the SQLite repository
      const revokeOutcome = await sqlEngine.revokeBlock(
        entryId,
        'Unblocking target account after audit',
        validReviewer,
        {
          network: 'testnet',
          accountId: 'defect-target.testnet',
          now: now + 5000,
        },
      );

      expect(revokeOutcome.revision).toBe(2);
      expect(sqlRepo.getLatestBlocklistRevision()).toBe(2);
      const activeBlock = sqlRepo.getActiveBlock('testnet', 'defect-target.testnet');
      expect(activeBlock).toBeNull();
    });
  });
});
