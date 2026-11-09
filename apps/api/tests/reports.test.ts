import 'node:crypto';
import {
  InMemoryGraphProvider,
  ReportRepository,
  createDatabase,
  runMigrations,
} from '@counterparty-guard/reputation';
import {
  type ReportSignablePayload,
  generateKeyPair,
  signReportPayload,
} from '@counterparty-guard/shared';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it } from 'vitest';
import { buildServer } from '../test-support/report-server.js';

describe('Reports API Service (apps/api/tests/reports.test.ts)', () => {
  let server: FastifyInstance;
  let repository: ReportRepository;
  const now = 1700000500000; // Fixed timestamp for deterministic testing

  const createValidPayload = (
    keyPair = generateKeyPair(),
    overrides: Partial<ReportSignablePayload> = {},
  ) => {
    const payload: ReportSignablePayload = {
      network: 'testnet',
      accused_account_id: 'drainer-malicious.testnet',
      reporter_id: `sentinel-${Math.random().toString(36).slice(2, 8)}.testnet`,
      reporter_public_key: keyPair.publicKey,
      category: 'drainer',
      description: 'Unauthorized sweep of contract balance using exploit permit.',
      transaction_references: ['9XyZ1234567890abcdef', '1AbCdEfGhIjKlMnOpQrS'],
      evidence_content_hashes: [],
      contract_code_hash: null,
      issued_at: now - 60_000,
      expires_at: now + 600_000,
      nonce: `nonce-${Date.now()}-${Math.random()}`,
      ...overrides,
    };

    const signature = signReportPayload(payload, keyPair.secretKey);
    return {
      payload,
      signedPayload: { ...payload, signature },
      keyPair,
    };
  };

  beforeEach(async () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    repository = new ReportRepository(db, () => now);

    server = await buildServer({
      repository,
      now: () => now,
      reviewerAuth: {
        reviewerTokens: ['reviewer-secret-token', 'admin-secret-token'],
      },
    });
  });

  describe('1. Server Baseline & Health', () => {
    it('returns status ok for GET /health', async () => {
      const res = await server.inject({
        method: 'GET',
        url: '/health',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.status).toBe('ok');
      expect(body.timestamp).toBe(now);
    });

    it('does not expose permissive cross-origin preflight', async () => {
      const res = await server.inject({
        method: 'OPTIONS',
        url: '/v1/reports',
        headers: {
          origin: 'http://localhost:5173',
          'access-control-request-method': 'POST',
        },
      });

      expect(res.statusCode).toBe(404);
      expect(res.headers['access-control-allow-origin']).toBeUndefined();
    });
  });

  describe('2. POST /v1/reports (Intake Validation & Ingestion)', () => {
    it('accepts and persists a valid signed report payload with 201 Created', async () => {
      const { signedPayload } = createValidPayload();

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.report_id).toBeDefined();
      expect(body.status).toBe('submitted');
      expect(body.issued_at).toBe(signedPayload.issued_at);
      expect(body.expires_at).toBe(signedPayload.expires_at);

      // Verify persistence in repository
      const saved = repository.getReport(body.report_id);
      expect(saved).not.toBeNull();
      expect(saved?.accused_account_id).toBe('drainer-malicious.testnet');
      expect(saved?.transaction_references).toEqual(signedPayload.transaction_references);
    });

    it('rejects malformed JSON payload with 400', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        headers: { 'content-type': 'application/json' },
        payload: '{"broken": json',
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects report missing required fields with 400', async () => {
      const { signedPayload } = createValidPayload();
      const { description: _omitted, ...invalid } = signedPayload;

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: invalid,
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBe('INVALID_SCHEMA');
    });

    it('rejects report with invalid category with 400', async () => {
      const { signedPayload } = createValidPayload();
      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: { ...signedPayload, category: 'non_existent_category' },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBe('INVALID_SCHEMA');
    });

    it('rejects temporal inversion (expires_at <= issued_at) with 400', async () => {
      const keyPair = generateKeyPair();
      const { signedPayload } = createValidPayload(keyPair, {
        issued_at: now,
        expires_at: now - 1000,
      });

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBe('EXPIRES_BEFORE_ISSUED');
    });

    it('rejects expired report (expires_at <= now) with 400', async () => {
      const keyPair = generateKeyPair();
      const { signedPayload } = createValidPayload(keyPair, {
        issued_at: now - 200_000,
        expires_at: now - 10_000,
      });

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBe('REPORT_EXPIRED');
    });

    it('rejects future issuance beyond clock skew tolerance with 400', async () => {
      const keyPair = generateKeyPair();
      const { signedPayload } = createValidPayload(keyPair, {
        issued_at: now + 600_000, // 10 min into future
        expires_at: now + 1_200_000,
      });

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBe('ISSUED_IN_FUTURE');
    });

    it('rejects duplicate nonce from same reporter with 409 NONCE_REPLAY_DETECTED', async () => {
      const keyPair = generateKeyPair();
      const { signedPayload } = createValidPayload(keyPair, {
        reporter_id: 'alice-auditor.testnet',
        nonce: 'fixed-nonce-12345',
      });

      // First submission succeeds
      const res1 = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      expect(res1.statusCode).toBe(201);

      // Replay identical nonce
      const res2 = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      expect(res2.statusCode).toBe(409);
      const body2 = JSON.parse(res2.body);
      expect(body2.error).toBe('NONCE_REPLAY_DETECTED');
    });

    it('allows identical nonce from a different reporter', async () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();

      const { signedPayload: p1 } = createValidPayload(keyPair1, {
        reporter_id: 'reporter-1.testnet',
        nonce: 'shared-nonce-unique',
      });
      const { signedPayload: p2 } = createValidPayload(keyPair2, {
        reporter_id: 'reporter-2.testnet',
        nonce: 'shared-nonce-unique',
      });

      const res1 = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: p1,
      });
      expect(res1.statusCode).toBe(201);

      const res2 = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: p2,
      });
      expect(res2.statusCode).toBe(201);
    });

    it('rejects invalid Ed25519 signature with 401 INVALID_SIGNATURE', async () => {
      const { signedPayload } = createValidPayload();
      const tampered = {
        ...signedPayload,
        signature:
          'ed25519:1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111',
      };

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: tampered,
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBe('INVALID_SIGNATURE');
    });

    it('rejects tampered report payload with 401 INVALID_SIGNATURE', async () => {
      const { signedPayload } = createValidPayload();
      const tampered = {
        ...signedPayload,
        description: 'Tampered description after signing occurred!',
      };

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: tampered,
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBe('INVALID_SIGNATURE');
    });

    it('rejects key mismatch for existing reporter with 403 REPORTER_KEY_MISMATCH', async () => {
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();

      const { signedPayload: p1 } = createValidPayload(kp1, {
        reporter_id: 'single-id-reporter.testnet',
      });
      const res1 = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: p1,
      });
      expect(res1.statusCode).toBe(201);

      const { signedPayload: p2 } = createValidPayload(kp2, {
        reporter_id: 'single-id-reporter.testnet',
      });
      const res2 = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: p2,
      });
      expect(res2.statusCode).toBe(403);
      const body2 = JSON.parse(res2.body);
      expect(body2.error).toBe('REPORTER_KEY_MISMATCH');
    });

    it('accepts and stores optional contract_code_hash', async () => {
      const { signedPayload } = createValidPayload(generateKeyPair(), {
        contract_code_hash: '1111111122222222333333334444444455555555666666667777777788888888',
      });

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      const saved = repository.getReport(body.report_id);
      expect(saved?.contract_code_hash).toBe(
        '1111111122222222333333334444444455555555666666667777777788888888',
      );
    });
  });

  describe('3. GET /v1/reports/:id (Report Query)', () => {
    it('returns 200 with report details and review history for existing report', async () => {
      const { signedPayload } = createValidPayload();
      const createRes = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(createRes.body);

      const res = await server.inject({
        method: 'GET',
        url: `/v1/reports/${report_id}`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.report.report_id).toBe(report_id);
      expect(body.report.category).toBe('drainer');
      expect(body.review_history).toEqual([]);
    });

    it('returns 404 for non-existent report ID', async () => {
      const res = await server.inject({
        method: 'GET',
        url: '/v1/reports/00000000-0000-0000-0000-000000000000',
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBe('NOT_FOUND');
    });

    it('includes dependence group details when report is part of a cluster', async () => {
      const { signedPayload } = createValidPayload();
      const createRes = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(createRes.body);

      // Create dependence group in repo
      repository.upsertDependenceGroup({
        group_id: 'group-sybil-01',
        network: 'testnet',
        common_funder_id: 'parent.testnet',
        faucet_exempted: 0,
        effective_weight: 1.0,
        reporter_count: 5,
        clustering_reason: 'Shared Hop-1 funder parent.testnet',
        created_at: now,
        updated_at: now,
      });
      repository.updateReportStatus(report_id, 'submitted', 'group-sybil-01');

      const res = await server.inject({
        method: 'GET',
        url: `/v1/reports/${report_id}`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.dependence_group).toBeDefined();
      expect(body.dependence_group.groupId).toBe('group-sybil-01');
      expect(body.dependence_group.reporterCount).toBe(5);
      expect(body.dependence_group.effectiveWeight).toBe(1.0);
      expect(body.dependence_group.commonFunderId).toBe('parent.testnet');
      expect(body.dependence_group.faucetExempted).toBe(false);
    });
  });

  describe('4. POST /v1/reports/:id/review (Reviewer Authority & Hard Block Control)', () => {
    let reportId: string;

    beforeEach(async () => {
      const { signedPayload } = createValidPayload();
      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      reportId = JSON.parse(res.body).report_id;
    });

    it('rejects review request with no authorization header (403 Forbidden)', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Confirmed malicious drainer',
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBe('FORBIDDEN');
    });

    it('rejects automated agent token with 403 Forbidden', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        headers: {
          authorization: 'Bearer agent-secret-token-12345',
        },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Autonomous agent attempting to hard block receiver',
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBe('FORBIDDEN');
      expect(body.message).toContain('Agent tokens are not permitted');
    });

    it('rejects unknown bearer token with 403 Forbidden', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        headers: {
          authorization: 'Bearer completely-invalid-token',
        },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Valid reason here',
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('strictly enforces whitelist when reviewerTokens is explicitly configured', async () => {
      const customServer = await buildServer({
        repository,
        now: () => now,
        reviewerAuth: { reviewerTokens: ['strict-custom-token'] },
      });

      const res = await customServer.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        headers: {
          authorization: 'Bearer reviewer-unlisted-prefix-token',
        },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Attempting review with unlisted token',
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('rejects review on expired report with 400 INVALID_TRANSITION', async () => {
      let currentTime = now;
      const expiringServer = await buildServer({
        repository,
        now: () => currentTime,
        reviewerAuth: { reviewerTokens: ['reviewer-secret-token'] },
      });

      const kp = generateKeyPair();
      const { signedPayload } = createValidPayload(kp, {
        issued_at: now - 10_000,
        expires_at: now + 5000,
      });
      const createRes = await expiringServer.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(createRes.body);

      currentTime = now + 10_000; // Past expiry

      const res = await expiringServer.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: {
          authorization: 'Bearer reviewer-secret-token',
        },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Attempting to review expired report',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBe('INVALID_TRANSITION');
    });

    it('rejects review on non-existent report with 404', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports/00000000-0000-0000-0000-000000000000/review',
        headers: {
          authorization: 'Bearer reviewer-secret-token',
        },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Confirmed malicious drainer',
        },
      });

      expect(res.statusCode).toBe(404);
    });

    it('rejects review payload with reason < 5 characters with 400', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        headers: {
          authorization: 'Bearer reviewer-secret-token',
        },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'bad', // too short (< 5 chars)
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBe('INVALID_SCHEMA');
    });

    it('active_block decision creates blocklist entry, updates status to reviewed, and increments revision', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        headers: {
          authorization: 'Bearer reviewer-secret-token',
          'x-reviewer-id': 'security-lead.testnet',
        },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Forensic audit confirmed unauthorized token sweep.',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.review_id).toBeDefined();
      expect(body.status).toBe('reviewed');
      expect(body.blocklist_revision).toBeGreaterThan(0);

      // Verify active block in repository
      const block = repository.getActiveBlock('testnet', 'drainer-malicious.testnet');
      expect(block).not.toBeNull();
      expect(block?.is_active).toBe(1);
      expect(block?.reviewer_id).toBe('configured-reviewer');

      // Verify report status updated
      const updatedReport = repository.getReport(reportId);
      expect(updatedReport?.status).toBe('reviewed');
    });

    it('dismissed decision transitions report to reviewed without active block', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        headers: {
          authorization: 'Bearer reviewer-secret-token',
        },
        payload: {
          decision: 'dismissed',
          scope: 'account',
          reason: 'False alarm: authorized tester activity.',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.status).toBe('reviewed');

      // No active block should exist
      const block = repository.getActiveBlock('testnet', 'drainer-malicious.testnet');
      expect(block).toBeNull();
    });

    it('corroborated decision transitions report to corroborated', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        headers: {
          authorization: 'Bearer reviewer-secret-token',
        },
        payload: {
          decision: 'corroborated',
          scope: 'account',
          reason: 'Multiple independent indicators observed.',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.status).toBe('corroborated');

      const updatedReport = repository.getReport(reportId);
      expect(updatedReport?.status).toBe('corroborated');
    });

    it('rejects review on report in terminal status (rejected) with 400', async () => {
      // First reject
      await server.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'rejected',
          reason: 'Rejected due to insufficient evidence.',
        },
      });

      // Second review should fail
      const res2 = await server.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'active_block',
          reason: 'Attempting to review a rejected report.',
        },
      });

      expect(res2.statusCode).toBe(400);
      const body2 = JSON.parse(res2.body);
      expect(body2.error).toBe('INVALID_TRANSITION');
    });
  });

  describe('5. GET /v1/receivers/:network/:account/reports (Receiver Reputation & Block Authority)', () => {
    it('returns empty reports and is_blocked: false for a clean account', async () => {
      const res = await server.inject({
        method: 'GET',
        url: '/v1/receivers/testnet/clean-merchant.testnet/reports',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.is_blocked).toBe(false);
      expect(body.total_reports).toBe(0);
      expect(body.effective_weight).toBe(0);
      expect(body.reports).toEqual([]);
      expect(body.dependence_groups).toEqual([]);
    });

    it('rejects invalid network parameter with 400', async () => {
      const res = await server.inject({
        method: 'GET',
        url: '/v1/receivers/invalidnet/clean-merchant.testnet/reports',
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBe('INVALID_NETWORK');
    });

    it('enforces Active Blocklist Authority: unreviewed reports CANNOT trigger hard block (is_blocked: false)', async () => {
      const target = 'unreviewed-target.testnet';

      // Submit 10 raw unreviewed reports against the target
      for (let i = 0; i < 10; i++) {
        const { signedPayload } = createValidPayload(generateKeyPair(), {
          accused_account_id: target,
          reporter_id: `sentinel-${i}.testnet`,
        });

        const res = await server.inject({
          method: 'POST',
          url: '/v1/reports',
          payload: signedPayload,
        });
        expect(res.statusCode).toBe(201);
      }

      // Query receiver reports
      const res = await server.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.total_reports).toBe(10);
      // HARD SECURITY INVARIANT ASSERTION:
      // Even with 10 unreviewed reports, is_blocked MUST remain false!
      expect(body.is_blocked).toBe(false);
    });

    it('reflects active block only after human reviewer commits active_block', async () => {
      const target = 'bad-actor.testnet';
      const { signedPayload } = createValidPayload(generateKeyPair(), {
        accused_account_id: target,
      });

      const createRes = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(createRes.body);

      // Verify unblocked initially
      const beforeRes = await server.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });
      expect(JSON.parse(beforeRes.body).is_blocked).toBe(false);

      // Reviewer executes active_block
      const reviewRes = await server.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Manual inspection verified honeypot code.',
        },
      });
      expect(reviewRes.statusCode).toBe(200);

      // Now query reports: is_blocked MUST be true
      const afterRes = await server.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });
      expect(afterRes.statusCode).toBe(200);
      const afterBody = JSON.parse(afterRes.body);
      expect(afterBody.is_blocked).toBe(true);
    });

    it('discounts coordinated Sybil reports to 1.0 aggregate weight (Scenario S4)', async () => {
      const target = 'popular-service.testnet';
      const commonFunder = 'sybil-parent.testnet';
      const graphProvider = new InMemoryGraphProvider();

      // Submit 5 reports whose reporters share a common direct funder in the graph
      for (let i = 0; i < 5; i++) {
        const reporterId = `sybil-bot-${i}.testnet`;
        const { signedPayload } = createValidPayload(generateKeyPair(), {
          accused_account_id: target,
          reporter_id: reporterId,
        });

        await server.inject({
          method: 'POST',
          url: '/v1/reports',
          payload: signedPayload,
        });

        // Edge 1: commonFunder funds reporterId
        graphProvider.addEdge({
          id: `fund-${i}`,
          source: commonFunder,
          target: reporterId,
          amountYocto: '1000000000000000000000000',
          timestamp: now - 3600_000,
          type: 'transfer',
        });
        // Edge 2: reporterId interacts with target
        graphProvider.addEdge({
          id: `call-${i}`,
          source: reporterId,
          target: target,
          amountYocto: '0',
          timestamp: now - 1800_000,
          type: 'contract_call',
        });
      }

      const sybilServer = await buildServer({
        repository,
        now: () => now,
        graphDataProvider: graphProvider,
      });

      const res = await sybilServer.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.total_reports).toBe(5);
      // Sybil capping: 5 reports sharing common funder capped at 1.0 total effective weight
      expect(body.effective_weight).toBeCloseTo(1.0, 2);
      expect(body.dependence_groups.length).toBeGreaterThanOrEqual(1);

      // Each individual report is discounted to ~0.2
      for (const r of body.reports) {
        expect(r.effective_weight).toBeCloseTo(0.2, 2);
      }
    });

    it('does not penalize accounts sharing a common testnet faucet (Scenario S6)', async () => {
      const target = 'service-target.testnet';
      const faucetAccount = 'faucet.testnet';
      const graphProvider = new InMemoryGraphProvider();

      for (let i = 0; i < 3; i++) {
        const reporterId = `legit-user-${i}.testnet`;
        const { signedPayload } = createValidPayload(generateKeyPair(), {
          accused_account_id: target,
          reporter_id: reporterId,
          transaction_references: [`fixture:independent-faucet-event-${i}`],
          evidence_content_hashes: [],
        });

        await server.inject({
          method: 'POST',
          url: '/v1/reports',
          payload: signedPayload,
        });

        // Funder is testnet faucet
        graphProvider.addEdge({
          id: `faucet-${i}`,
          source: faucetAccount,
          target: reporterId,
          amountYocto: '50000000000000000000000000',
          timestamp: now - 3600_000,
          type: 'transfer',
        });
        // Edge: reporter interacts with target
        graphProvider.addEdge({
          id: `call-legit-${i}`,
          source: reporterId,
          target: target,
          amountYocto: '0',
          timestamp: now - 1800_000,
          type: 'contract_call',
        });
      }

      const faucetServer = await buildServer({
        repository,
        now: () => now,
        graphDataProvider: graphProvider,
      });

      const res = await faucetServer.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.total_reports).toBe(3);
      // Faucet exemption: NOT discounted or clustered into Sybil group
      expect(body.effective_weight).toBeCloseTo(3.0, 2);
      for (const r of body.reports) {
        expect(r.effective_weight).toBeCloseTo(1.0, 2);
      }
    });

    it('ignores expired active blocks (produces is_blocked: false)', async () => {
      const target = 'rehabilitated.testnet';
      const { signedPayload } = createValidPayload(generateKeyPair(), {
        accused_account_id: target,
      });

      const createRes = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(createRes.body);

      // Create an expired active block
      await server.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Temporary quarantine',
          block_expires_at: now - 1000, // already expired
        },
      });

      const res = await server.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.is_blocked).toBe(false);
    });
  });
});
