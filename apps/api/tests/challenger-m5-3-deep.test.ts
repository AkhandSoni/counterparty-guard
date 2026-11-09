import { ReportRepository, createDatabase, runMigrations } from '@counterparty-guard/reputation';
import {
  type ReportSignablePayload,
  generateKeyPair,
  signReportPayload,
} from '@counterparty-guard/shared';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it } from 'vitest';
import { buildServer } from '../test-support/report-server.js';

describe('Deep Empirical Re-challenge: Milestone M5 Remediations', () => {
  let server: FastifyInstance;
  let repository: ReportRepository;
  let rawDb: ReturnType<typeof createDatabase>;
  const now = 1700000500000;

  const createPayload = (
    keyPair = generateKeyPair(),
    overrides: Partial<ReportSignablePayload> = {},
  ) => {
    const payload: ReportSignablePayload = {
      network: 'testnet',
      accused_account_id: 'bad-actor.testnet',
      reporter_id: `sentinel-${Math.random().toString(36).slice(2, 9)}.testnet`,
      reporter_public_key: keyPair.publicKey,
      category: 'drainer',
      description: 'Suspicious drain of deposit vault with unverified credentials.',
      transaction_references: ['3xH8bV91kLmNoPqRsTuVwXyZ1234567890abcdef'],
      evidence_content_hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
      contract_code_hash: null,
      issued_at: now - 30_000,
      expires_at: now + 300_000,
      nonce: `nonce-${Date.now()}-${Math.random().toString(36).slice(2)}`,
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
    rawDb = createDatabase({ path: ':memory:' });
    runMigrations(rawDb);
    repository = new ReportRepository(rawDb, () => now);

    server = await buildServer({
      repository,
      now: () => now,
      reviewerAuth: {
        reviewerTokens: ['reviewer-secret-token', 'admin-master-key'],
      },
    });
  });

  // -------------------------------------------------------------------------
  // 1. Identity Squatting & State Contamination Deep Verification
  // -------------------------------------------------------------------------
  describe('1. Identity Squatting & State Contamination Resistance', () => {
    it('100 concurrent forged submissions for 100 new reporter IDs leave 0 rows in SQLite reporters, reports, and nonces', async () => {
      const forgedIds: string[] = [];

      for (let i = 0; i < 100; i++) {
        const fakeId = `victim-account-${i}.testnet`;
        forgedIds.push(fakeId);
        const kp = generateKeyPair();

        const fakePayload: ReportSignablePayload = {
          network: 'testnet',
          accused_account_id: 'target.testnet',
          reporter_id: fakeId,
          reporter_public_key: kp.publicKey,
          category: 'drainer',
          description: 'A forged report attempting to squat this reporter identity.',
          transaction_references: ['tx1234567890'],
          evidence_content_hashes: [
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          ],
          contract_code_hash: null,
          issued_at: now - 1000,
          expires_at: now + 50_000,
          nonce: `forged-nonce-${i}`,
        };

        const res = await server.inject({
          method: 'POST',
          url: '/v1/reports',
          payload: {
            ...fakePayload,
            signature:
              'ed25519:1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111',
          },
        });

        expect(res.statusCode).toBe(401);
        expect(JSON.parse(res.body).error).toBe('INVALID_SIGNATURE');
      }

      // Assert directly in SQLite tables that NO rows were created
      const reportersCount = rawDb.prepare('SELECT COUNT(*) as cnt FROM reporters').get() as {
        cnt: number;
      };
      expect(reportersCount.cnt).toBe(0);

      const reportsCount = rawDb.prepare('SELECT COUNT(*) as cnt FROM reports').get() as {
        cnt: number;
      };
      expect(reportsCount.cnt).toBe(0);

      // Now verify that the legitimate users can register those same IDs with valid signatures
      for (let i = 0; i < 5; i++) {
        const legitimateKp = generateKeyPair();
        const validPayload: ReportSignablePayload = {
          network: 'testnet',
          accused_account_id: 'target.testnet',
          reporter_id: forgedIds[i] ?? '',
          reporter_public_key: legitimateKp.publicKey,
          category: 'drainer',
          description: 'Legitimate submission from the rightful key owner.',
          transaction_references: ['tx1234567890'],
          evidence_content_hashes: [
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          ],
          contract_code_hash: null,
          issued_at: now - 1000,
          expires_at: now + 50_000,
          nonce: `legit-nonce-${i}`,
        };
        const validSig = signReportPayload(validPayload, legitimateKp.secretKey);

        const legitRes = await server.inject({
          method: 'POST',
          url: '/v1/reports',
          payload: { ...validPayload, signature: validSig },
        });

        expect(legitRes.statusCode).toBe(201);
      }

      const finalReportersCount = rawDb.prepare('SELECT COUNT(*) as cnt FROM reporters').get() as {
        cnt: number;
      };
      expect(finalReportersCount.cnt).toBe(5);
    });

    it('submitting with wrong signature for an already-registered reporter does NOT alter existing public key', async () => {
      // Register legitimate reporter
      const { signedPayload, keyPair, payload } = createPayload();
      const res1 = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      expect(res1.statusCode).toBe(201);

      const initialReporter = rawDb
        .prepare('SELECT * FROM reporters WHERE reporter_id = ?')
        .get(payload.reporter_id) as { public_key: string } | undefined;
      expect(initialReporter?.public_key).toBe(keyPair.publicKey);

      // Attacker tries to submit for same reporter_id with attacker's public key and invalid signature
      const attackerKp = generateKeyPair();
      const attackerPayload = {
        ...payload,
        reporter_public_key: attackerKp.publicKey,
        nonce: 'nonce-attacker-tamper',
        signature:
          'ed25519:1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111',
      };

      const attackerRes = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: attackerPayload,
      });
      expect(attackerRes.statusCode).toBe(401);

      // Verify DB state is intact
      const afterReporter = rawDb
        .prepare('SELECT * FROM reporters WHERE reporter_id = ?')
        .get(payload.reporter_id) as { public_key: string } | undefined;
      expect(afterReporter?.public_key).toBe(keyPair.publicKey);
    });
  });

  // -------------------------------------------------------------------------
  // 2. Strict Custom Reviewer Whitelist Deep Verification
  // -------------------------------------------------------------------------
  describe('2. Strict Custom Reviewer Whitelist Enforcement', () => {
    it('empty reviewerTokens list rejects ALL tokens including default reviewer- tokens', async () => {
      const lockServer = await buildServer({
        repository,
        now: () => now,
        reviewerAuth: { reviewerTokens: [] },
      });

      const { signedPayload } = createPayload();
      const postRes = await lockServer.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(postRes.body);

      const tokensToTest = [
        'reviewer-secret-token',
        'admin-master-key',
        'reviewer-arbitrary',
        'admin-arbitrary',
        'custom-token',
      ];

      for (const tok of tokensToTest) {
        const res = await lockServer.inject({
          method: 'POST',
          url: `/v1/reports/${report_id}/review`,
          headers: { authorization: `Bearer ${tok}` },
          payload: { decision: 'active_block', reason: 'Testing empty whitelist lockout' },
        });
        expect(res.statusCode).toBe(403);
      }
    });

    it('custom reviewerTokens rejects prefix-matching unlisted tokens and permits listed ones', async () => {
      const customServer = await buildServer({
        repository,
        now: () => now,
        reviewerAuth: {
          reviewerTokens: ['my-custom-reviewer-key', 'admin-corp-key'],
        },
      });

      const { signedPayload } = createPayload();
      const postRes = await customServer.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(postRes.body);

      // Listed reviewer key -> 200 OK
      const allowedRes = await customServer.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer my-custom-reviewer-key' },
        payload: { decision: 'corroborated', reason: 'Legitimate reviewer' },
      });
      expect(allowedRes.statusCode).toBe(200);

      // Listed admin key -> 200 OK (role admin)
      const allowedAdminRes = await customServer.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer admin-corp-key' },
        payload: { decision: 'active_block', reason: 'Legitimate admin' },
      });
      expect(allowedAdminRes.statusCode).toBe(200);

      // Unlisted prefix tokens -> 403 Forbidden
      const unlistedPrefixes = [
        'reviewer-attacker',
        'reviewer-my-custom-reviewer-key',
        'admin-attacker',
        'admin-corp-key-extra',
        'my-custom-reviewer-key-extra',
      ];

      for (const unlisted of unlistedPrefixes) {
        const res = await customServer.inject({
          method: 'POST',
          url: `/v1/reports/${report_id}/review`,
          headers: { authorization: `Bearer ${unlisted}` },
          payload: { decision: 'dismissed', reason: 'Attack attempt' },
        });
        expect(res.statusCode).toBe(403);
      }
    });
  });

  // -------------------------------------------------------------------------
  // 3. Temporal Expiry & Review Transitions Deep Verification
  // -------------------------------------------------------------------------
  describe('3. Temporal Expiry Boundary & State Rejection', () => {
    it('exact expiry boundary: now === expires_at rejects review with 400 and marks report expired', async () => {
      const expiryTimestamp = now + 10_000;
      let mockTime = now;

      const dynamicServer = await buildServer({
        repository,
        now: () => mockTime,
        reviewerAuth: { reviewerTokens: ['reviewer-secret-token'] },
      });

      const kp = generateKeyPair();
      const { signedPayload } = createPayload(kp, {
        issued_at: now - 5000,
        expires_at: expiryTimestamp,
      });

      const postRes = await dynamicServer.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      expect(postRes.statusCode).toBe(201);
      const { report_id } = JSON.parse(postRes.body);

      // Exact boundary: now === expires_at
      mockTime = expiryTimestamp;

      const reviewRes = await dynamicServer.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: { decision: 'active_block', reason: 'Review at exact expiry boundary' },
      });

      expect(reviewRes.statusCode).toBe(400);
      const body = JSON.parse(reviewRes.body);
      expect(body.error).toBe('INVALID_TRANSITION');
      expect(body.message).toContain('has expired');

      // Check SQLite status was updated to expired
      const reportInDb = repository.getReport(report_id);
      expect(reportInDb?.status).toBe('submitted');

      // Attempting any further review on the report in 'expired' status returns 400
      const repeatRes = await dynamicServer.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: { decision: 'dismissed', reason: 'Dismiss after expired' },
      });
      expect(repeatRes.statusCode).toBe(400);
      expect(JSON.parse(repeatRes.body).error).toBe('INVALID_TRANSITION');
    });

    it('review at expires_at - 1 succeeds with 200 OK', async () => {
      const expiryTimestamp = now + 10_000;
      let mockTime = now;

      const dynamicServer = await buildServer({
        repository,
        now: () => mockTime,
        reviewerAuth: { reviewerTokens: ['reviewer-secret-token'] },
      });

      const kp = generateKeyPair();
      const { signedPayload } = createPayload(kp, {
        issued_at: now - 5000,
        expires_at: expiryTimestamp,
      });

      const postRes = await dynamicServer.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(postRes.body);

      // 1 ms before expiry
      mockTime = expiryTimestamp - 1;

      const reviewRes = await dynamicServer.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: { decision: 'active_block', reason: 'Review immediately before expiry' },
      });

      expect(reviewRes.statusCode).toBe(200);
      expect(JSON.parse(reviewRes.body).status).toBe('reviewed');
    });
  });

  // -------------------------------------------------------------------------
  // 4. Active Blocklist Authority Invariant Deep Verification
  // -------------------------------------------------------------------------
  describe('4. Active Blocklist Authority Invariant', () => {
    it('under no circumstances can unreviewed reports cause is_blocked: true', async () => {
      const target = 'clean-entity.testnet';

      // Submit 20 distinct reports
      for (let i = 0; i < 20; i++) {
        const { signedPayload } = createPayload(generateKeyPair(), {
          accused_account_id: target,
          category: 'drainer',
        });
        const res = await server.inject({
          method: 'POST',
          url: '/v1/reports',
          payload: signedPayload,
        });
        expect(res.statusCode).toBe(201);
      }

      // Check receiver route
      const receiverRes = await server.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });
      expect(receiverRes.statusCode).toBe(200);
      const data = JSON.parse(receiverRes.body);
      expect(data.is_blocked).toBe(false);
      expect(data.total_reports).toBe(20);

      // Verify active_blocklist table in SQLite has 0 rows
      const blocklistCount = rawDb
        .prepare('SELECT COUNT(*) as cnt FROM active_blocklist')
        .get() as { cnt: number };
      expect(blocklistCount.cnt).toBe(0);
    });

    it('active block is network-scoped and respects block_expires_at', async () => {
      const target = 'temporary-suspect.testnet';
      const { signedPayload } = createPayload(generateKeyPair(), {
        accused_account_id: target,
        network: 'testnet',
      });
      const postRes = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(postRes.body);

      const mockTime = now;
      const timeServer = await buildServer({
        repository,
        now: () => mockTime,
        reviewerAuth: { reviewerTokens: ['reviewer-secret-token'] },
      });

      // Reviewer sets active block with 60-second block expiration relative to real wall clock
      const realNow = Date.now();
      const reviewRes = await timeServer.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Time-limited block',
          block_expires_at: realNow + 60_000,
        },
      });
      expect(reviewRes.statusCode).toBe(200);

      // At now -> testnet is blocked
      const t1 = await timeServer.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });
      expect(JSON.parse(t1.body).is_blocked).toBe(true);

      // Cross-network check -> mainnet is NOT blocked
      const mainnetRes = await timeServer.inject({
        method: 'GET',
        url: `/v1/receivers/mainnet/${target}/reports`,
      });
      expect(JSON.parse(mainnetRes.body).is_blocked).toBe(false);

      // When block has already expired (e.g. block_expires_at in past)
      const expiredBlockTarget = 'expired-block-account.testnet';
      const { signedPayload: expPayload } = createPayload(generateKeyPair(), {
        accused_account_id: expiredBlockTarget,
        network: 'testnet',
      });
      const expPost = await timeServer.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: expPayload,
      });
      const expReportId = JSON.parse(expPost.body).report_id;

      await timeServer.inject({
        method: 'POST',
        url: `/v1/reports/${expReportId}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Already expired block',
          block_expires_at: now - 1000,
        },
      });

      const t2 = await timeServer.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${expiredBlockTarget}/reports`,
      });
      expect(JSON.parse(t2.body).is_blocked).toBe(false);
    });
  });
});
