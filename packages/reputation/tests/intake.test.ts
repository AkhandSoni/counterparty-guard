import {
  type ReportSignablePayload,
  generateKeyPair,
  serializeReportForSigning,
  signDetached,
  signReportPayload,
} from '@counterparty-guard/shared';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  IntakeException,
  getHttpStatusForIntakeErrorCode,
  submitReport,
  validateAndSubmitReport,
} from '../src/intake.js';
import { createDatabase } from '../src/storage/db.js';
import { InMemoryReportStorage } from '../src/storage/memory.js';
import { runMigrations } from '../src/storage/migrations.js';
import { ReportRepository } from '../src/storage/repository.js';

describe('Signed Report Intake Pipeline (intake.test.ts)', () => {
  let storage: InMemoryReportStorage;
  const now = 1700000500000; // Reference current time

  const createValidPayload = (
    keyPair = generateKeyPair(),
    overrides: Partial<ReportSignablePayload> = {},
  ): {
    payload: ReportSignablePayload;
    signedPayload: Record<string, unknown>;
    secretKey: Uint8Array;
  } => {
    const payload: ReportSignablePayload = {
      network: 'testnet',
      accused_account_id: 'drainer-scam.testnet',
      reporter_id: 'sentinel-auditor.testnet',
      reporter_public_key: keyPair.publicKey,
      category: 'drainer',
      description: 'Unauthorized sweep of contract balance using exploit permit.',
      transaction_references: ['9XyZ1234567890abcdef', '1AbCdEfGhIjKlMnOpQrS'],
      evidence_content_hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
      contract_code_hash: null,
      issued_at: now - 60_000, // 1 min ago
      expires_at: now + 600_000, // 10 min from now
      nonce: `nonce-${Date.now()}-${Math.random()}`,
      ...overrides,
    };

    const signature = signReportPayload(payload, keyPair.secretKey);
    return {
      payload,
      signedPayload: { ...payload, signature },
      secretKey: keyPair.secretKey,
    };
  };

  beforeEach(() => {
    storage = new InMemoryReportStorage();
  });

  describe('1. Happy Path Intake', () => {
    it('accepts valid signed report, assigns UUID, sets status to submitted, and registers reporter', async () => {
      const kp = generateKeyPair();
      const { signedPayload } = createValidPayload(kp);

      const result = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(result.success).toBe(true);
      if (!result.success) return;

      expect(result.data.status).toBe('submitted');
      expect(result.data.report_id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
      expect(result.data.issued_at).toBe(signedPayload.issued_at);
      expect(result.data.expires_at).toBe(signedPayload.expires_at);

      // Verify persistence in storage
      const stored = await storage.getReport(result.data.report_id);
      expect(stored).not.toBeNull();
      expect(stored?.status).toBe('submitted');
      expect(stored?.reporter_id).toBe(signedPayload.reporter_id);

      // Verify reporter registration
      const reporter = await storage.getReporter(String(signedPayload.reporter_id));
      expect(reporter).not.toBeNull();
      expect(reporter?.public_key).toBe(kp.publicKey);
    });

    it('works with stringified JSON input', async () => {
      const { signedPayload } = createValidPayload();
      const jsonString = JSON.stringify(signedPayload);

      const result = await validateAndSubmitReport(jsonString, { storage, now });
      expect(result.success).toBe(true);
    });

    it('supports throwing convenience wrapper submitReport', async () => {
      const { signedPayload } = createValidPayload();
      const response = await submitReport(signedPayload, { storage, now });
      expect(response.status).toBe('submitted');
      expect(response.report_id).toBeDefined();
    });
  });

  describe('2. Nonce Replay Protection', () => {
    it('rejects exact report resubmission with NONCE_REPLAY_DETECTED (HTTP 409)', async () => {
      const kp = generateKeyPair();
      const { signedPayload } = createValidPayload(kp, { nonce: 'fixed-nonce-001' });

      // First submission succeeds
      const first = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(first.success).toBe(true);

      // Second submission with identical nonce fails
      const second = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(second.success).toBe(false);
      if (second.success) return;

      expect(second.error.code).toBe('NONCE_REPLAY_DETECTED');
      expect(getHttpStatusForIntakeErrorCode(second.error.code)).toBe(409);
    });

    it('allows identical nonce used by a DIFFERENT reporter', async () => {
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();

      const { signedPayload: p1 } = createValidPayload(kp1, {
        reporter_id: 'reporter-1.testnet',
        nonce: 'shared-nonce-val',
      });
      const { signedPayload: p2 } = createValidPayload(kp2, {
        reporter_id: 'reporter-2.testnet',
        nonce: 'shared-nonce-val',
      });

      const res1 = await validateAndSubmitReport(p1, { storage, now });
      const res2 = await validateAndSubmitReport(p2, { storage, now });

      expect(res1.success).toBe(true);
      expect(res2.success).toBe(true);
    });

    it('throws IntakeException with code NONCE_REPLAY_DETECTED via submitReport', async () => {
      const { signedPayload } = createValidPayload();
      await submitReport(signedPayload, { storage, now });

      await expect(submitReport(signedPayload, { storage, now })).rejects.toThrow(IntakeException);
    });
  });

  describe('3. Domain-Separated Cryptographic Verification', () => {
    it('rejects cross-domain signature signed under COUNTERPARTY_GUARD_PERMIT_V1', async () => {
      const kp = generateKeyPair();
      const { payload } = createValidPayload(kp);

      // Maliciously serialized under permit domain
      const crossDomainBytes = serializeReportForSigning(payload, 'COUNTERPARTY_GUARD_PERMIT_V1');
      const forgedSig = signDetached(crossDomainBytes, kp.secretKey);

      const forgedPayload = { ...payload, signature: forgedSig };
      const result = await validateAndSubmitReport(forgedPayload, { storage, now });

      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error.code).toBe('INVALID_SIGNATURE');
      expect(getHttpStatusForIntakeErrorCode(result.error.code)).toBe(401);
    });

    it('rejects tampered description with INVALID_SIGNATURE', async () => {
      const { signedPayload } = createValidPayload();
      const tampered = {
        ...signedPayload,
        description: 'Tampered description altering the original claim.',
      };

      const result = await validateAndSubmitReport(tampered, { storage, now });
      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error.code).toBe('INVALID_SIGNATURE');
    });

    it('rejects tampered category with INVALID_SIGNATURE', async () => {
      const { signedPayload } = createValidPayload(undefined, { category: 'drainer' });
      const tampered = { ...signedPayload, category: 'phishing' };

      const result = await validateAndSubmitReport(tampered, { storage, now });
      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error.code).toBe('INVALID_SIGNATURE');
    });

    it('rejects tampered accused_account_id with INVALID_SIGNATURE', async () => {
      const { signedPayload } = createValidPayload();
      const tampered = { ...signedPayload, accused_account_id: 'innocent-victim.testnet' };

      const result = await validateAndSubmitReport(tampered, { storage, now });
      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error.code).toBe('INVALID_SIGNATURE');
    });

    it('rejects signature signed with different key', async () => {
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();
      const { payload } = createValidPayload(kp1);

      // Sign with kp2 secret key while claiming kp1 public key
      const forgedSig = signReportPayload(payload, kp2.secretKey);
      const forgedPayload = { ...payload, signature: forgedSig };

      const result = await validateAndSubmitReport(forgedPayload, { storage, now });
      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error.code).toBe('INVALID_SIGNATURE');
    });

    it('does not register an unauthenticated reporter in storage if signature verification fails', async () => {
      const kp = generateKeyPair();
      const unregisteredReporterId = 'unregistered-target.testnet';
      const { payload } = createValidPayload(kp, { reporter_id: unregisteredReporterId });
      const badSigPayload = {
        ...payload,
        signature:
          'ed25519:1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111',
      };

      const result = await validateAndSubmitReport(badSigPayload, { storage, now });
      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error.code).toBe('INVALID_SIGNATURE');

      // Crucial assertion: the reporter should NOT be registered in storage
      const storedReporter = await storage.getReporter(unregisteredReporterId);
      expect(storedReporter).toBeNull();
    });
  });

  describe('4. Temporal Expiry & Clock Skew Validation', () => {
    it('rejects expired report (expires_at <= now) with REPORT_EXPIRED', async () => {
      const kp = generateKeyPair();
      const { signedPayload } = createValidPayload(kp, {
        issued_at: now - 3600_000, // 1 hr ago
        expires_at: now - 60_000, // expired 1 min ago
      });

      const result = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error.code).toBe('REPORT_EXPIRED');
      expect(getHttpStatusForIntakeErrorCode(result.error.code)).toBe(400);
    });

    it('rejects inverted expiry (expires_at <= issued_at) with EXPIRES_BEFORE_ISSUED', async () => {
      const kp = generateKeyPair();
      const payload: ReportSignablePayload = {
        network: 'testnet',
        accused_account_id: 'drainer.testnet',
        reporter_id: 'sentinel.testnet',
        reporter_public_key: kp.publicKey,
        category: 'drainer',
        description: 'Testing invalid inverted expiry timeline.',
        transaction_references: [],
        evidence_content_hashes: [],
        contract_code_hash: null,
        issued_at: now + 5000,
        expires_at: now + 1000, // expires BEFORE issued
        nonce: 'nonce-inverted',
      };
      // Manually construct signature to bypass signReportPayload safety
      const sig = signReportPayload(
        { ...payload, expires_at: payload.issued_at + 10_000 },
        kp.secretKey,
      );
      const rawPayload = { ...payload, signature: sig };

      const result = await validateAndSubmitReport(rawPayload, { storage, now });
      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error.code).toBe('EXPIRES_BEFORE_ISSUED');
    });

    it('rejects future issued_at exceeding clock skew tolerance with ISSUED_IN_FUTURE', async () => {
      const kp = generateKeyPair();
      const { signedPayload } = createValidPayload(kp, {
        issued_at: now + 600_000, // 10 min into future (> default 5 min skew tolerance)
        expires_at: now + 1200_000,
      });

      const result = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error.code).toBe('ISSUED_IN_FUTURE');
    });

    it('accepts future issued_at within acceptable clock skew tolerance (e.g. 2 minutes)', async () => {
      const kp = generateKeyPair();
      const { signedPayload } = createValidPayload(kp, {
        issued_at: now + 120_000, // 2 min ahead, within 5 min tolerance
        expires_at: now + 1200_000,
      });

      const result = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(result.success).toBe(true);
    });
  });

  describe('5. Reporter Key Immutability', () => {
    it('rejects submission if reporter_id is already registered with different public key', async () => {
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();

      // Register reporter with kp1
      await storage.registerReporter({
        reporter_id: 'sentinel-auditor.testnet',
        public_key: kp1.publicKey,
        created_at: now - 1000,
      });

      // Attacker attempts to submit using kp2 claiming to be sentinel-auditor.testnet
      const { signedPayload } = createValidPayload(kp2, {
        reporter_id: 'sentinel-auditor.testnet',
      });

      const result = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error.code).toBe('REPORTER_KEY_MISMATCH');
      expect(getHttpStatusForIntakeErrorCode(result.error.code)).toBe(403);
    });
  });

  describe('6. Zod Schema Validation', () => {
    it('rejects description with fewer than 10 characters with INVALID_SCHEMA', async () => {
      const kp = generateKeyPair();
      const { signedPayload } = createValidPayload(kp, {
        description: 'short',
      });

      const result = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error.code).toBe('INVALID_SCHEMA');
    });

    it('rejects malformed JSON string with MALFORMED_JSON', async () => {
      const result = await validateAndSubmitReport('{ invalid json syntax ', { storage, now });
      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error.code).toBe('MALFORMED_JSON');
      expect(getHttpStatusForIntakeErrorCode(result.error.code)).toBe(400);
    });
  });

  describe('7. Integration with SQLite ReportRepository', () => {
    it('persists report and registers reporter in real SQLite database', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const kp = generateKeyPair();
      const { signedPayload } = createValidPayload(kp);

      const result = await validateAndSubmitReport(signedPayload, { storage: repo, now });
      expect(result.success).toBe(true);
      if (!result.success) return;

      const reportInDb = repo.getReport(result.data.report_id);
      expect(reportInDb).not.toBeNull();
      expect(reportInDb?.status).toBe('submitted');
      expect(reportInDb?.reporter_id).toBe(signedPayload.reporter_id);

      // Verify second submission with same nonce fails at DB constraint level
      const replay = await validateAndSubmitReport(signedPayload, { storage: repo, now });
      expect(replay.success).toBe(false);
      if (replay.success) return;
      expect(replay.error.code).toBe('NONCE_REPLAY_DETECTED');
    });
  });
});
