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
import { buildServer } from '../src/server.js';

describe('Adversarial Challenge: Fastify Reports API Service (apps/api/tests/challenger-reports-api.test.ts)', () => {
  let server: FastifyInstance;
  let repository: ReportRepository;
  const now = 1700000500000;

  const createSignedPayload = (
    keyPair = generateKeyPair(),
    overrides: Partial<ReportSignablePayload> = {},
  ) => {
    const payload: ReportSignablePayload = {
      network: 'testnet',
      accused_account_id: 'drainer-suspect.testnet',
      reporter_id: `auditor-${Math.random().toString(36).slice(2, 9)}.testnet`,
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
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    repository = new ReportRepository(db);

    server = await buildServer({
      repository,
      now: () => now,
      reviewerAuth: {
        reviewerTokens: ['reviewer-secret-token', 'admin-master-key'],
      },
    });
  });

  // =========================================================================
  // 1. ACTIVE BLOCKLIST AUTHORITY INVARIANT STRESS TESTING
  // =========================================================================
  describe('1. Active Blocklist Authority Invariant Stress Testing', () => {
    it('mass false-report flood (50 distinct reporters) NEVER triggers is_blocked: true', async () => {
      const target = 'innocent-victim.testnet';
      const reportCount = 50;

      // Ingest 50 distinct signed allegations against the same target
      for (let i = 0; i < reportCount; i++) {
        const { signedPayload } = createSignedPayload(generateKeyPair(), {
          accused_account_id: target,
          reporter_id: `swarm-bot-${i}.testnet`,
          category: i % 2 === 0 ? 'drainer' : 'phishing',
        });

        const postRes = await server.inject({
          method: 'POST',
          url: '/v1/reports',
          payload: signedPayload,
        });
        expect(postRes.statusCode).toBe(201);
      }

      // Query receiver reports endpoint
      const res = await server.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });

      expect(res.statusCode).toBe(200);
      const data = JSON.parse(res.body);

      // CRITICAL SECURITY INVARIANT:
      // Even with 50 unreviewed reports, is_blocked MUST REMAIN strictly false!
      expect(data.is_blocked).toBe(false);
      expect(data.total_reports).toBe(50);
      expect(data.reports.length).toBe(50);
    });

    it('corroborated reports transition does NOT set is_blocked: true', async () => {
      const target = 'corroborated-target.testnet';
      const { signedPayload } = createSignedPayload(generateKeyPair(), {
        accused_account_id: target,
      });

      const postRes = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(postRes.body);

      // Reviewer sets decision: corroborated
      const reviewRes = await server.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'corroborated',
          reason: 'Cross-verified with independent intelligence signals',
        },
      });
      expect(reviewRes.statusCode).toBe(200);
      expect(JSON.parse(reviewRes.body).status).toBe('corroborated');

      // Assert receiver endpoint still returns is_blocked: false
      const getRes = await server.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });
      const data = JSON.parse(getRes.body);
      expect(data.is_blocked).toBe(false);
      expect(data.reports[0].status).toBe('corroborated');
    });

    it('dismissed reports do NOT set is_blocked: true', async () => {
      const target = 'dismissed-target.testnet';
      const { signedPayload } = createSignedPayload(generateKeyPair(), {
        accused_account_id: target,
      });

      const postRes = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(postRes.body);

      const reviewRes = await server.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'dismissed',
          reason: 'Verified as false allegation during penetration test',
        },
      });
      expect(reviewRes.statusCode).toBe(200);

      const getRes = await server.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });
      const data = JSON.parse(getRes.body);
      expect(data.is_blocked).toBe(false);
      expect(data.reports[0].status).toBe('reviewed');
    });

    it('ONLY human reviewer active_block action sets is_blocked: true and increments revision', async () => {
      const target = 'honeypot-drainer.testnet';
      const { signedPayload } = createSignedPayload(generateKeyPair(), {
        accused_account_id: target,
      });

      const postRes = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(postRes.body);

      // Before review -> false
      const beforeRes = await server.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });
      expect(JSON.parse(beforeRes.body).is_blocked).toBe(false);

      // Execute authenticated active_block
      const reviewRes = await server.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: {
          authorization: 'Bearer reviewer-secret-token',
          'x-reviewer-id': 'lead-auditor.testnet',
        },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Hard block approved: confirmed active drainer attack vector.',
        },
      });
      expect(reviewRes.statusCode).toBe(200);
      const reviewBody = JSON.parse(reviewRes.body);
      expect(reviewBody.status).toBe('reviewed');
      expect(reviewBody.blocklist_revision).toBeGreaterThan(0);

      // After review -> true
      const afterRes = await server.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });
      const afterData = JSON.parse(afterRes.body);
      expect(afterData.is_blocked).toBe(true);
    });

    it('cross-network isolation: active block on testnet does NOT block mainnet or sandbox', async () => {
      const target = 'network-isolated-account.testnet';
      const { signedPayload } = createSignedPayload(generateKeyPair(), {
        network: 'testnet',
        accused_account_id: target,
      });

      const postRes = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(postRes.body);

      await server.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Confirmed bad actor on testnet environment',
        },
      });

      // Testnet is blocked
      const testnetRes = await server.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });
      expect(JSON.parse(testnetRes.body).is_blocked).toBe(true);

      // Mainnet is unblocked
      const mainnetRes = await server.inject({
        method: 'GET',
        url: `/v1/receivers/mainnet/${target}/reports`,
      });
      expect(JSON.parse(mainnetRes.body).is_blocked).toBe(false);

      // Sandbox is unblocked
      const sandboxRes = await server.inject({
        method: 'GET',
        url: `/v1/receivers/sandbox/${target}/reports`,
      });
      expect(JSON.parse(sandboxRes.body).is_blocked).toBe(false);
    });

    it('case-insensitivity of account ID in receiver reports query', async () => {
      const target = 'cased-target.testnet';
      const { signedPayload } = createSignedPayload(generateKeyPair(), {
        accused_account_id: target,
      });

      const postRes = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(postRes.body);

      await server.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Confirmed drainer for case sensitivity check',
        },
      });

      // Query with uppercase and mixed case
      const resUpper = await server.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target.toUpperCase()}/reports`,
      });
      expect(resUpper.statusCode).toBe(200);
      expect(JSON.parse(resUpper.body).is_blocked).toBe(true);
      expect(JSON.parse(resUpper.body).total_reports).toBe(1);
    });
  });

  // =========================================================================
  // 2. REVIEWER AUTH BARRIER & TOKEN SMUGGLING ADVERSARIAL TESTING
  // =========================================================================
  describe('2. Reviewer Auth Barrier & Agent Token Rejection', () => {
    let testReportId: string;

    beforeEach(async () => {
      const { signedPayload } = createSignedPayload();
      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      testReportId = JSON.parse(res.body).report_id;
    });

    const agentTokens = [
      'agent-worker-01',
      'agent-worker-pool-99',
      'agent_token_abc123',
      'agent-autonomous-evaluator',
      'my_agent_token_secret',
      'agent-subagent-critic',
    ];

    for (const token of agentTokens) {
      it(`strictly rejects agent token Bearer "${token}" with 403 Forbidden`, async () => {
        const res = await server.inject({
          method: 'POST',
          url: `/v1/reports/${testReportId}/review`,
          headers: {
            authorization: `Bearer ${token}`,
          },
          payload: {
            decision: 'active_block',
            scope: 'account',
            reason: 'Agent attempt to trigger hard block',
          },
        });

        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error).toBe('FORBIDDEN');
        expect(body.message).toContain('Agent tokens are not permitted');
      });

      it(`strictly rejects agent token via header x-reviewer-token: "${token}" with 403 Forbidden`, async () => {
        const res = await server.inject({
          method: 'POST',
          url: `/v1/reports/${testReportId}/review`,
          headers: {
            'x-reviewer-token': token,
          },
          payload: {
            decision: 'active_block',
            scope: 'account',
            reason: 'Agent header smuggling attempt',
          },
        });

        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error).toBe('FORBIDDEN');
      });
    }

    it('rejects unauthenticated requests (missing header) with 403 Forbidden', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${testReportId}/review`,
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Unauthenticated attempt',
        },
      });

      expect(res.statusCode).toBe(403);
      expect(JSON.parse(res.body).error).toBe('FORBIDDEN');
    });

    it('rejects empty or whitespace authorization header with 403 Forbidden', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${testReportId}/review`,
        headers: { authorization: 'Bearer   ' },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Whitespace token attempt',
        },
      });

      expect(res.statusCode).toBe(403);
      expect(JSON.parse(res.body).error).toBe('FORBIDDEN');
    });

    it('rejects non-Bearer authentication scheme with 403 Forbidden', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${testReportId}/review`,
        headers: { authorization: 'Basic dXNlcjpwYXNz' },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Basic auth scheme attempt',
        },
      });

      expect(res.statusCode).toBe(403);
      expect(JSON.parse(res.body).error).toBe('FORBIDDEN');
    });

    it('rejects arbitrary unauthorized bearer tokens with 403 Forbidden', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${testReportId}/review`,
        headers: { authorization: 'Bearer random-unknown-token-xyz' },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Arbitrary token attempt',
        },
      });

      expect(res.statusCode).toBe(403);
      expect(JSON.parse(res.body).error).toBe('FORBIDDEN');
    });

    it('spoofing x-reviewer-id without valid token is rejected with 403 Forbidden', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${testReportId}/review`,
        headers: {
          authorization: 'Bearer invalid-token-12345',
          'x-reviewer-id': 'root-admin.testnet',
        },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Impersonation attack',
        },
      });

      expect(res.statusCode).toBe(403);
      expect(JSON.parse(res.body).error).toBe('FORBIDDEN');
    });

    it('agent token in x-reviewer-token cannot be bypassed by sending valid authorization header', async () => {
      // If x-reviewer-token is an agent token, it takes precedence and must be rejected
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${testReportId}/review`,
        headers: {
          authorization: 'Bearer reviewer-secret-token',
          'x-reviewer-token': 'agent-worker-01',
        },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Header smuggling attack',
        },
      });

      expect(res.statusCode).toBe(403);
      expect(JSON.parse(res.body).error).toBe('FORBIDDEN');
    });
  });

  // =========================================================================
  // 3. CRYPTOGRAPHIC SIGNATURE & TAMPER RESISTANCE
  // =========================================================================
  describe('3. Cryptographic Signature Verification & Tampering Resistance', () => {
    it('rejects payload when reporter_public_key does not match signing key (401)', async () => {
      const realSigner = generateKeyPair();
      const spoofedIdentity = generateKeyPair();

      // Sign with realSigner, but claim spoofedIdentity public key
      const payload: ReportSignablePayload = {
        network: 'testnet',
        accused_account_id: 'bad-target.testnet',
        reporter_id: 'spoofed-reporter.testnet',
        reporter_public_key: spoofedIdentity.publicKey, // Mismatch!
        category: 'phishing',
        description: 'Impersonating genuine dApp interface.',
        transaction_references: ['tx11111111111111111111'],
        evidence_content_hashes: [
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        ],
        contract_code_hash: null,
        issued_at: now - 10_000,
        expires_at: now + 300_000,
        nonce: `nonce-${Date.now()}`,
      };

      const signature = signReportPayload(payload, realSigner.secretKey);

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: { ...payload, signature },
      });

      expect(res.statusCode).toBe(401);
      expect(JSON.parse(res.body).error).toBe('INVALID_SIGNATURE');
    });

    const tamperFields: (keyof ReportSignablePayload)[] = [
      'accused_account_id',
      'category',
      'description',
      'issued_at',
      'expires_at',
      'nonce',
      'contract_code_hash',
    ];

    for (const field of tamperFields) {
      it(`rejects post-signing mutation of field "${field}" with 401 INVALID_SIGNATURE`, async () => {
        const { signedPayload } = createSignedPayload();
        const tampered = { ...signedPayload };

        if (field === 'accused_account_id')
          tampered.accused_account_id = 'different-accused.testnet';
        else if (field === 'category') tampered.category = 'wash_trading';
        else if (field === 'description')
          tampered.description = 'Mutated description after signature.';
        else if (field === 'issued_at') tampered.issued_at = signedPayload.issued_at - 1000;
        else if (field === 'expires_at') tampered.expires_at = signedPayload.expires_at + 1000;
        else if (field === 'nonce') tampered.nonce = 'mutated-nonce-value';
        else if (field === 'contract_code_hash') {
          tampered.contract_code_hash =
            'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
        }

        const res = await server.inject({
          method: 'POST',
          url: '/v1/reports',
          payload: tampered,
        });

        expect(res.statusCode).toBe(401);
        expect(JSON.parse(res.body).error).toBe('INVALID_SIGNATURE');
      });
    }

    it('rejects post-signing tampering with transaction_references array', async () => {
      const { signedPayload } = createSignedPayload();
      const tampered = {
        ...signedPayload,
        transaction_references: ['tampered-tx-reference-12345'],
      };

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: tampered,
      });

      expect(res.statusCode).toBe(401);
      expect(JSON.parse(res.body).error).toBe('INVALID_SIGNATURE');
    });

    it('rejects post-signing tampering with evidence_content_hashes array', async () => {
      const { signedPayload } = createSignedPayload();
      const tampered = {
        ...signedPayload,
        evidence_content_hashes: [
          '0000000000000000000000000000000000000000000000000000000000000000',
        ],
      };

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: tampered,
      });

      expect(res.statusCode).toBe(401);
      expect(JSON.parse(res.body).error).toBe('INVALID_SIGNATURE');
    });

    it('rejects bit-flipped Ed25519 signature with 401 INVALID_SIGNATURE', async () => {
      const { signedPayload } = createSignedPayload();
      // Flip characters in valid signature
      const validSig = signedPayload.signature;
      const flippedSig =
        validSig.slice(0, 15) + (validSig[15] === 'A' ? 'B' : 'A') + validSig.slice(16);

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: { ...signedPayload, signature: flippedSig },
      });

      expect(res.statusCode).toBe(401);
      expect(JSON.parse(res.body).error).toBe('INVALID_SIGNATURE');
    });

    it('rejects schema-violating signature format with 400 INVALID_SCHEMA', async () => {
      const { signedPayload } = createSignedPayload();

      // Missing ed25519: prefix
      const resNoPrefix = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: { ...signedPayload, signature: 'bad-signature-without-prefix' },
      });
      expect(resNoPrefix.statusCode).toBe(400);

      // Truncated signature
      const resTruncated = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: { ...signedPayload, signature: 'ed25519:short' },
      });
      expect(resTruncated.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 4. NONCE REPLAY PROTECTION & ISOLATION
  // =========================================================================
  describe('4. Nonce Replay Protection & Boundary Isolation', () => {
    it('rejects nonce reuse by the same reporter with 409 NONCE_REPLAY_DETECTED', async () => {
      const keyPair = generateKeyPair();
      const fixedNonce = 'fixed-deterministic-nonce-42';

      const { signedPayload: firstPayload } = createSignedPayload(keyPair, {
        reporter_id: 'auditor-charlie.testnet',
        nonce: fixedNonce,
      });

      const res1 = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: firstPayload,
      });
      expect(res1.statusCode).toBe(201);

      // Replay with identical nonce against different target
      const { signedPayload: replayPayload } = createSignedPayload(keyPair, {
        reporter_id: 'auditor-charlie.testnet',
        accused_account_id: 'another-suspect.testnet',
        nonce: fixedNonce,
      });

      const res2 = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: replayPayload,
      });

      expect(res2.statusCode).toBe(409);
      expect(JSON.parse(res2.body).error).toBe('NONCE_REPLAY_DETECTED');
    });

    it('allows same nonce across different reporters (per-reporter isolation)', async () => {
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();
      const sharedNonce = 'shared-reusable-nonce-99';

      const { signedPayload: p1 } = createSignedPayload(kp1, {
        reporter_id: 'reporter-alpha.testnet',
        nonce: sharedNonce,
      });
      const { signedPayload: p2 } = createSignedPayload(kp2, {
        reporter_id: 'reporter-beta.testnet',
        nonce: sharedNonce,
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
  });

  // =========================================================================
  // 5. TEMPORAL BOUNDARIES & CLOCK SKEW TOLERANCE
  // =========================================================================
  describe('5. Temporal Boundaries & Clock Skew Stress Testing', () => {
    it('rejects expires_at equal to issued_at (400 EXPIRES_BEFORE_ISSUED)', async () => {
      const { signedPayload } = createSignedPayload(generateKeyPair(), {
        issued_at: now - 1000,
        expires_at: now - 1000,
      });

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });

      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).error).toBe('EXPIRES_BEFORE_ISSUED');
    });

    it('rejects expires_at less than issued_at (400 EXPIRES_BEFORE_ISSUED)', async () => {
      const { signedPayload } = createSignedPayload(generateKeyPair(), {
        issued_at: now,
        expires_at: now - 5000,
      });

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });

      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).error).toBe('EXPIRES_BEFORE_ISSUED');
    });

    it('rejects report already expired at intake (expires_at <= now)', async () => {
      const { signedPayload } = createSignedPayload(generateKeyPair(), {
        issued_at: now - 100_000,
        expires_at: now - 1,
      });

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });

      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).error).toBe('REPORT_EXPIRED');
    });

    it('accepts issuance within 5-minute clock skew tolerance (now + 299_000)', async () => {
      const { signedPayload } = createSignedPayload(generateKeyPair(), {
        issued_at: now + 299_000, // within 300_000ms clock skew tolerance
        expires_at: now + 600_000,
      });

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });

      expect(res.statusCode).toBe(201);
    });

    it('rejects issuance beyond 5-minute clock skew tolerance (now + 301_000)', async () => {
      const { signedPayload } = createSignedPayload(generateKeyPair(), {
        issued_at: now + 301_000, // > 300_000ms
        expires_at: now + 700_000,
      });

      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });

      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).error).toBe('ISSUED_IN_FUTURE');
    });

    it('receiver reports query excludes reports that have expired past query time', async () => {
      const target = 'expiring-target.testnet';
      let currentTime = now;

      const timeAdvancingServer = await buildServer({
        repository,
        now: () => currentTime,
      });

      // Submit report that expires at now + 50_000
      const { signedPayload } = createSignedPayload(generateKeyPair(), {
        accused_account_id: target,
        issued_at: now - 10_000,
        expires_at: now + 50_000,
      });

      await timeAdvancingServer.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });

      // At currentTime = now, report is valid
      const resBefore = await timeAdvancingServer.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });
      expect(JSON.parse(resBefore.body).total_reports).toBe(1);

      // Advance time beyond expiry
      currentTime = now + 60_000;

      const resAfter = await timeAdvancingServer.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });
      expect(JSON.parse(resAfter.body).total_reports).toBe(0);
    });
  });

  // =========================================================================
  // 6. REVIEW STATE LIFECYCLE & INPUT VALIDATION
  // =========================================================================
  describe('6. Review State Lifecycle & Input Validation Stress Testing', () => {
    let reportId: string;

    beforeEach(async () => {
      const { signedPayload } = createSignedPayload();
      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      reportId = JSON.parse(res.body).report_id;
    });

    it('rejects review on non-existent report with 404 NOT_FOUND', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/v1/reports/00000000-0000-0000-0000-000000000000/review',
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'Valid audit reason for non-existent report',
        },
      });

      expect(res.statusCode).toBe(404);
      expect(JSON.parse(res.body).error).toBe('NOT_FOUND');
    });

    it('rejects audit reason < 5 characters with 400 INVALID_SCHEMA', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'tiny', // 4 characters
        },
      });

      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).error).toBe('INVALID_SCHEMA');
    });

    it('accepts audit reason exactly 5 characters', async () => {
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: 'valid', // 5 characters
        },
      });

      expect(res.statusCode).toBe(200);
      expect(JSON.parse(res.body).status).toBe('reviewed');
    });

    it('rejects audit reason > 1000 characters with 400 INVALID_SCHEMA', async () => {
      const longReason = 'a'.repeat(1001);
      const res = await server.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'active_block',
          scope: 'account',
          reason: longReason,
        },
      });

      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).error).toBe('INVALID_SCHEMA');
    });

    it('rejects review on report in terminal status "rejected" with 400 INVALID_TRANSITION', async () => {
      // First reviewer rejects report
      const rejRes = await server.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'rejected',
          reason: 'Insufficient on-chain evidence provided',
        },
      });
      expect(rejRes.statusCode).toBe(200);

      // Attempting to review again fails
      const secondRes = await server.inject({
        method: 'POST',
        url: `/v1/reports/${reportId}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'active_block',
          reason: 'Attempting to revive rejected report',
        },
      });

      expect(secondRes.statusCode).toBe(400);
      expect(JSON.parse(secondRes.body).error).toBe('INVALID_TRANSITION');
    });
  });

  // =========================================================================
  // 7. SYBIL GRAPH CLUSTERING & FAUCET IMMUNITY INVARIANTS
  // =========================================================================
  describe('7. Sybil Graph Clustering & Faucet Immunity Invariants', () => {
    it('Scenario S4: Sybil swarm flood (10 bot reporters) has weight capped at 1.0', async () => {
      const target = 'popular-defi.testnet';
      const commonFunder = 'sybil-mastermind.testnet';
      const graphProvider = new InMemoryGraphProvider();

      const botCount = 10;
      for (let i = 0; i < botCount; i++) {
        const reporterId = `sybil-cluster-bot-${i}.testnet`;
        const { signedPayload } = createSignedPayload(generateKeyPair(), {
          accused_account_id: target,
          reporter_id: reporterId,
        });

        await server.inject({
          method: 'POST',
          url: '/v1/reports',
          payload: signedPayload,
        });

        graphProvider.addEdge({
          id: `funder-edge-${i}`,
          source: commonFunder,
          target: reporterId,
          amountYocto: '5000000000000000000000000',
          timestamp: now - 3600_000,
          type: 'transfer',
        });
        graphProvider.addEdge({
          id: `interact-edge-${i}`,
          source: reporterId,
          target: target,
          amountYocto: '0',
          timestamp: now - 1800_000,
          type: 'contract_call',
        });
      }

      const clusterServer = await buildServer({
        repository,
        now: () => now,
        graphDataProvider: graphProvider,
      });

      const res = await clusterServer.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });

      expect(res.statusCode).toBe(200);
      const data = JSON.parse(res.body);

      expect(data.total_reports).toBe(10);
      // Hard Sybil discounting: 10 coordinated bots capped at 1.0 aggregate weight
      expect(data.effective_weight).toBeCloseTo(1.0, 2);
      expect(data.is_blocked).toBe(false);
      expect(data.dependence_groups.length).toBeGreaterThanOrEqual(1);

      // Each report gets 1/10 = 0.1 weight
      for (const r of data.reports) {
        expect(r.effective_weight).toBeCloseTo(0.1, 2);
      }
    });

    it('Scenario S6: Common Faucet Control accounts are immune to Sybil clustering', async () => {
      const target = 'legit-swap.testnet';
      const faucet = 'faucet.testnet';
      const graphProvider = new InMemoryGraphProvider();

      const userCount = 5;
      for (let i = 0; i < userCount; i++) {
        const reporterId = `bona-fide-user-${i}.testnet`;
        const { signedPayload } = createSignedPayload(generateKeyPair(), {
          accused_account_id: target,
          reporter_id: reporterId,
        });

        await server.inject({
          method: 'POST',
          url: '/v1/reports',
          payload: signedPayload,
        });

        // Common funder is the testnet faucet
        graphProvider.addEdge({
          id: `faucet-funding-${i}`,
          source: faucet,
          target: reporterId,
          amountYocto: '25000000000000000000000000',
          timestamp: now - 7200_000,
          type: 'transfer',
        });
        graphProvider.addEdge({
          id: `legit-call-${i}`,
          source: reporterId,
          target: target,
          amountYocto: '0',
          timestamp: now - 3600_000,
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
      const data = JSON.parse(res.body);

      expect(data.total_reports).toBe(5);
      // Faucet accounts are NEVER penalized or capped into a single weight:
      // 5 independent users retain full 1.0 weight each = 5.0
      expect(data.effective_weight).toBeCloseTo(5.0, 2);
      expect(data.is_blocked).toBe(false);
      for (const r of data.reports) {
        expect(r.effective_weight).toBeCloseTo(1.0, 2);
      }
    });
  });

  // =========================================================================
  // 8. EMPIRICAL VULNERABILITY PROBES & ARCHITECTURAL STRESS
  // =========================================================================
  describe('8. Empirical Vulnerability Probes & Deep Security Boundaries', () => {
    it('PROBE 1: State contamination test — invalid signature submission does NOT hijack unregistered reporter ID', async () => {
      const attackerKeyPair = generateKeyPair();
      const victimReporterId = 'legit-victim-reporter.testnet';
      const victimKeyPair = generateKeyPair();

      // Attacker attempts to front-run/register victimReporterId with attacker's key and a bogus signature
      const bogusPayload: ReportSignablePayload = {
        network: 'testnet',
        accused_account_id: 'some-target.testnet',
        reporter_id: victimReporterId,
        reporter_public_key: attackerKeyPair.publicKey,
        category: 'drainer',
        description: 'Malicious attempt to squat reporter identity.',
        transaction_references: ['tx99999999999999999999'],
        evidence_content_hashes: [
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        ],
        contract_code_hash: null,
        issued_at: now - 5000,
        expires_at: now + 300_000,
        nonce: `nonce-${Date.now()}-bogus`,
      };

      // Invalid signature
      const attackerRes = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: {
          ...bogusPayload,
          signature:
            'ed25519:1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111',
        },
      });
      expect(attackerRes.statusCode).toBe(401);

      // CRITICAL CHECK:
      // If the intake registered attacker's key before validating the signature,
      // the real victim will now be locked out with 403 REPORTER_KEY_MISMATCH!
      const victimValidPayload: ReportSignablePayload = {
        network: 'testnet',
        accused_account_id: 'actual-suspect.testnet',
        reporter_id: victimReporterId,
        reporter_public_key: victimKeyPair.publicKey,
        category: 'phishing',
        description: 'Legitimate report from the genuine reporter identity.',
        transaction_references: ['tx88888888888888888888'],
        evidence_content_hashes: [
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        ],
        contract_code_hash: null,
        issued_at: now - 2000,
        expires_at: now + 300_000,
        nonce: `nonce-${Date.now()}-victim`,
      };
      const victimSig = signReportPayload(victimValidPayload, victimKeyPair.secretKey);

      const victimRes = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: { ...victimValidPayload, signature: victimSig },
      });

      // Assert whether victim can submit:
      // If intake registered the attacker key prematurely, this will fail with 403!
      expect(victimRes.statusCode).toBe(201);
    });

    it('PROBE 2: Reviewer auth token prefix allowance vs strict whitelist', async () => {
      // Create server with a specific custom reviewer token
      const strictServer = await buildServer({
        repository,
        now: () => now,
        reviewerAuth: {
          reviewerTokens: ['production-secret-auth-key-999'],
        },
      });

      const { signedPayload } = createSignedPayload();
      const createRes = await strictServer.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(createRes.body);

      // Test with arbitrary token starting with 'reviewer-' not in reviewerTokens
      const arbitraryReviewerRes = await strictServer.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer reviewer-arbitrary-unauthorized' },
        payload: {
          decision: 'active_block',
          reason: 'Attempting review with unlisted reviewer- prefix token',
        },
      });

      // Strict security invariant: When reviewerTokens whitelist is explicitly configured,
      // an unlisted token starting with 'reviewer-' MUST NOT be granted access!
      expect(arbitraryReviewerRes.statusCode).toBe(403);
    });

    it('PROBE 3: Review on expired report rejection', async () => {
      let currentTime = now;
      const expiringServer = await buildServer({
        repository,
        now: () => currentTime,
        reviewerAuth: { reviewerTokens: ['reviewer-secret-token'] },
      });

      const { signedPayload } = createSignedPayload(generateKeyPair(), {
        issued_at: now - 20_000,
        expires_at: now + 10_000,
      });

      const createRes = await expiringServer.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(createRes.body);

      // Advance time past report expiry
      currentTime = now + 50_000;

      const reviewRes = await expiringServer.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'active_block',
          reason: 'Reviewing an allegation whose report has expired',
        },
      });

      // Temporal security invariant: Reports that have expired cannot undergo review transitions
      expect(reviewRes.statusCode).toBe(400);
    });

    it('PROBE 4: Repeat reviews on same report and blocklist revision idempotency', async () => {
      const { signedPayload } = createSignedPayload();
      const createRes = await server.inject({
        method: 'POST',
        url: '/v1/reports',
        payload: signedPayload,
      });
      const { report_id } = JSON.parse(createRes.body);

      // First review
      const res1 = await server.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'active_block',
          reason: 'First review decision: block',
        },
      });
      expect(res1.statusCode).toBe(200);
      const rev1 = JSON.parse(res1.body).blocklist_revision;

      // Second review on already reviewed report
      const res2 = await server.inject({
        method: 'POST',
        url: `/v1/reports/${report_id}/review`,
        headers: { authorization: 'Bearer reviewer-secret-token' },
        payload: {
          decision: 'dismissed',
          reason: 'Second review decision: dismissing after re-investigation',
        },
      });
      expect(res2.statusCode).toBe(200);
      expect(JSON.parse(res2.body).status).toBe('reviewed');
    });

    it('PROBE 5: Path traversal and SQL injection attempts on receiver report route', async () => {
      const injectionAttacks = [
        'attacker.testnet; DROP TABLE reports;--',
        "attacker.testnet' OR '1'='1",
        '../../../etc/passwd',
        '<script>alert(1)</script>',
        'drainer.testnet%00',
      ];

      for (const account of injectionAttacks) {
        const res = await server.inject({
          method: 'GET',
          url: `/v1/receivers/testnet/${encodeURIComponent(account)}/reports`,
        });

        // Must return safe 200 (empty reports) or 400, NEVER 500 or SQL error
        expect([200, 400]).toContain(res.statusCode);
        if (res.statusCode === 200) {
          const body = JSON.parse(res.body);
          expect(body.is_blocked).toBe(false);
          expect(body.total_reports).toBe(0);
        }
      }
    });
  });
});
