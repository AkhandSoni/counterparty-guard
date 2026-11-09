import 'node:crypto';
import {
  type ReportSignablePayload,
  formatSignature,
  generateKeyPair,
  parseSignature,
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

describe('Adversarial Boundary & Stress Testing (intake.ts & storage)', () => {
  let storage: InMemoryReportStorage;
  const now = 1700000000000; // Fixed epoch for reproducible assertions

  const createSignedPayload = (
    keyPair = generateKeyPair(),
    overrides: Partial<ReportSignablePayload> = {},
  ): {
    payload: ReportSignablePayload;
    signedPayload: Record<string, unknown>;
    secretKey: Uint8Array;
  } => {
    const payload: ReportSignablePayload = {
      network: 'testnet',
      accused_account_id: 'adversary-target.testnet',
      reporter_id: 'sentinel-challenger.testnet',
      reporter_public_key: keyPair.publicKey,
      category: 'drainer',
      description: 'Adversarial boundary test report payload exceeding 10 characters.',
      transaction_references: ['9XyZ1234567890abcdef', '1AbCdEfGhIjKlMnOpQrS'],
      evidence_content_hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
      contract_code_hash: null,
      issued_at: now - 30_000,
      expires_at: now + 300_000,
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

  // =========================================================================
  // 1. DUPLICATE NONCES FOR SAME REPORTER THROW 409
  // =========================================================================
  describe('1. Duplicate Nonce Replay Protection (HTTP 409)', () => {
    it('throws IntakeException with HTTP 409 and code NONCE_REPLAY_DETECTED via submitReport (in-memory)', async () => {
      const kp = generateKeyPair();
      const fixedNonce = 'challenger-nonce-fixed-101';
      const { signedPayload } = createSignedPayload(kp, { nonce: fixedNonce });

      // First submission passes
      const firstRes = await submitReport(signedPayload, { storage, now });
      expect(firstRes.status).toBe('submitted');

      // Second submission with exact same reporter and nonce must throw 409
      let caughtError: unknown;
      try {
        await submitReport(signedPayload, { storage, now });
      } catch (err) {
        caughtError = err;
      }

      expect(caughtError).toBeInstanceOf(IntakeException);
      const intakeEx = caughtError as IntakeException;
      expect(intakeEx.code).toBe('NONCE_REPLAY_DETECTED');
      expect(intakeEx.httpStatus).toBe(409);
      expect(getHttpStatusForIntakeErrorCode(intakeEx.code)).toBe(409);
    });

    it('returns validation failure with NONCE_REPLAY_DETECTED via validateAndSubmitReport', async () => {
      const kp = generateKeyPair();
      const fixedNonce = 'challenger-nonce-fixed-102';
      const { signedPayload } = createSignedPayload(kp, { nonce: fixedNonce });

      const first = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(first.success).toBe(true);

      const replay = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(replay.success).toBe(false);
      if (replay.success) return;

      expect(replay.error.code).toBe('NONCE_REPLAY_DETECTED');
      expect(getHttpStatusForIntakeErrorCode(replay.error.code)).toBe(409);
    });

    it('rejects replayed nonce even when payload fields (description, category, issued_at) are altered', async () => {
      const kp = generateKeyPair();
      const fixedNonce = 'reused-nonce-multi-payload';

      const { signedPayload: payload1 } = createSignedPayload(kp, {
        nonce: fixedNonce,
        description: 'First allegation description for target.',
        category: 'drainer',
      });
      const first = await validateAndSubmitReport(payload1, { storage, now });
      expect(first.success).toBe(true);

      // Construct a new signed report using the SAME nonce but altered contents
      const { signedPayload: payload2 } = createSignedPayload(kp, {
        nonce: fixedNonce,
        description: 'Completely different second allegation text.',
        category: 'phishing',
      });

      const replay = await validateAndSubmitReport(payload2, { storage, now });
      expect(replay.success).toBe(false);
      if (replay.success) return;

      expect(replay.error.code).toBe('NONCE_REPLAY_DETECTED');
      expect(getHttpStatusForIntakeErrorCode(replay.error.code)).toBe(409);
    });

    it('permits identical nonce when submitted by a DIFFERENT reporter (nonce isolation)', async () => {
      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();
      const sharedNonce = 'independent-shared-nonce-001';

      const { signedPayload: p1 } = createSignedPayload(kp1, {
        reporter_id: 'auditor-alpha.testnet',
        nonce: sharedNonce,
      });
      const { signedPayload: p2 } = createSignedPayload(kp2, {
        reporter_id: 'auditor-beta.testnet',
        nonce: sharedNonce,
      });

      const res1 = await validateAndSubmitReport(p1, { storage, now });
      const res2 = await validateAndSubmitReport(p2, { storage, now });

      expect(res1.success).toBe(true);
      expect(res2.success).toBe(true);
    });

    it('enforces duplicate nonce rejection in real SQLite ReportRepository and maps constraint to 409', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const kp = generateKeyPair();
      const fixedNonce = 'sqlite-fixed-nonce-999';
      const { signedPayload } = createSignedPayload(kp, { nonce: fixedNonce });

      const res1 = await submitReport(signedPayload, { storage: repo, now });
      expect(res1.status).toBe('submitted');

      // Duplicate via submitReport
      await expect(submitReport(signedPayload, { storage: repo, now })).rejects.toThrow(
        IntakeException,
      );

      // Verify direct error properties
      try {
        await submitReport(signedPayload, { storage: repo, now });
      } catch (err) {
        expect(err).toBeInstanceOf(IntakeException);
        expect((err as IntakeException).code).toBe('NONCE_REPLAY_DETECTED');
        expect((err as IntakeException).httpStatus).toBe(409);
      }
    });

    it('handles concurrent simultaneous duplicate submissions in SQLite gracefully (only 1 succeeds, others 409)', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const kp = generateKeyPair();
      const concurrentNonce = 'concurrent-nonce-race-001';
      const { signedPayload } = createSignedPayload(kp, { nonce: concurrentNonce });

      // Run 5 concurrent submissions with the same nonce
      const results = await Promise.all([
        validateAndSubmitReport(signedPayload, { storage: repo, now }),
        validateAndSubmitReport(signedPayload, { storage: repo, now }),
        validateAndSubmitReport(signedPayload, { storage: repo, now }),
        validateAndSubmitReport(signedPayload, { storage: repo, now }),
        validateAndSubmitReport(signedPayload, { storage: repo, now }),
      ]);

      const successes = results.filter((r) => r.success);
      const failures = results.filter((r) => !r.success);

      expect(successes.length).toBe(1);
      expect(failures.length).toBe(4);

      for (const f of failures) {
        if (!f.success) {
          expect(f.error.code).toBe('NONCE_REPLAY_DETECTED');
          expect(getHttpStatusForIntakeErrorCode(f.error.code)).toBe(409);
        }
      }
    });
  });

  // =========================================================================
  // 2. REPLAY OF PAYLOAD ACROSS DOMAINS FAILS SIGNATURE CHECK
  // =========================================================================
  describe('2. Cross-Domain Signature Replay Rejection (HTTP 401)', () => {
    it('rejects report signed under COUNTERPARTY_GUARD_PERMIT_V1 domain with INVALID_SIGNATURE (401)', async () => {
      const kp = generateKeyPair();
      const { payload } = createSignedPayload(kp);

      // Serialize under permit domain separator
      const forgedBytes = serializeReportForSigning(payload, 'COUNTERPARTY_GUARD_PERMIT_V1');
      const forgedSig = signDetached(forgedBytes, kp.secretKey);
      const crossDomainPayload = { ...payload, signature: forgedSig };

      const result = await validateAndSubmitReport(crossDomainPayload, { storage, now });
      expect(result.success).toBe(false);
      if (result.success) return;

      expect(result.error.code).toBe('INVALID_SIGNATURE');
      expect(getHttpStatusForIntakeErrorCode(result.error.code)).toBe(401);

      // Ensure submitReport throws IntakeException with 401
      await expect(submitReport(crossDomainPayload, { storage, now })).rejects.toThrow(
        IntakeException,
      );
    });

    it('rejects report signed with empty string domain separator', async () => {
      const kp = generateKeyPair();
      const { payload } = createSignedPayload(kp);

      const emptyDomainBytes = serializeReportForSigning(payload, '');
      const forgedSig = signDetached(emptyDomainBytes, kp.secretKey);
      const forgedPayload = { ...payload, signature: forgedSig };

      const result = await validateAndSubmitReport(forgedPayload, { storage, now });
      expect(result.success).toBe(false);
      if (result.success) return;

      expect(result.error.code).toBe('INVALID_SIGNATURE');
      expect(getHttpStatusForIntakeErrorCode(result.error.code)).toBe(401);
    });

    it('rejects report signed under external or foreign domain (e.g. NEAR_TX_V1, ETH_EIP712)', async () => {
      const kp = generateKeyPair();
      const { payload } = createSignedPayload(kp);

      for (const domain of ['NEAR_TX_V1', 'ETHEREUM_EIP712_V1', 'SOLANA_MESSAGE_V1']) {
        const bytes = serializeReportForSigning(payload, domain);
        const sig = signDetached(bytes, kp.secretKey);
        const res = await validateAndSubmitReport({ ...payload, signature: sig }, { storage, now });

        expect(res.success).toBe(false);
        if (!res.success) {
          expect(res.error.code).toBe('INVALID_SIGNATURE');
          expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(401);
        }
      }
    });

    it('rejects report signed with domain extension or prefix mutation (e.g. COUNTERPARTY_GUARD_REPORT_V1_EXTENDED)', async () => {
      const kp = generateKeyPair();
      const { payload } = createSignedPayload(kp);

      const mutatedDomain = 'COUNTERPARTY_GUARD_REPORT_V1_EXTENDED';
      const bytes = serializeReportForSigning(payload, mutatedDomain);
      const sig = signDetached(bytes, kp.secretKey);

      const res = await validateAndSubmitReport({ ...payload, signature: sig }, { storage, now });
      expect(res.success).toBe(false);
      if (!res.success) {
        expect(res.error.code).toBe('INVALID_SIGNATURE');
        expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(401);
      }
    });

    it('rejects report signed with lower-case domain separator (case-sensitivity)', async () => {
      const kp = generateKeyPair();
      const { payload } = createSignedPayload(kp);

      const lowerDomain = 'counterparty_guard_report_v1';
      const bytes = serializeReportForSigning(payload, lowerDomain);
      const sig = signDetached(bytes, kp.secretKey);

      const res = await validateAndSubmitReport({ ...payload, signature: sig }, { storage, now });
      expect(res.success).toBe(false);
      if (!res.success) {
        expect(res.error.code).toBe('INVALID_SIGNATURE');
      }
    });
  });

  // =========================================================================
  // 3. BIT-FLIPPED SIGNATURES FAIL
  // =========================================================================
  describe('3. Bit-Flipped & Tampered Signatures Fail Cryptographic Verification', () => {
    it('fails when flipping bit 0 of byte 0 (MSB & LSB) in valid Ed25519 signature', async () => {
      const kp = generateKeyPair();
      const { payload } = createSignedPayload(kp);
      const validSig = signReportPayload(payload, kp.secretKey);

      const sigBytes = parseSignature(validSig);
      sigBytes[0] ^= 0x01; // flip LSB of first byte
      const flippedSig = formatSignature(sigBytes);

      const res = await validateAndSubmitReport(
        { ...payload, signature: flippedSig },
        { storage, now },
      );
      expect(res.success).toBe(false);
      if (res.success) return;

      expect(res.error.code).toBe('INVALID_SIGNATURE');
      expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(401);

      await expect(
        submitReport({ ...payload, signature: flippedSig }, { storage, now }),
      ).rejects.toThrow(IntakeException);
    });

    it('fails when flipping bit in byte 31 (R component boundary)', async () => {
      const kp = generateKeyPair();
      const { payload } = createSignedPayload(kp);
      const validSig = signReportPayload(payload, kp.secretKey);

      const sigBytes = parseSignature(validSig);
      sigBytes[31] ^= 0x80; // flip MSB of 32nd byte
      const flippedSig = formatSignature(sigBytes);

      const res = await validateAndSubmitReport(
        { ...payload, signature: flippedSig },
        { storage, now },
      );
      expect(res.success).toBe(false);
      if (res.success) return;

      expect(res.error.code).toBe('INVALID_SIGNATURE');
      expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(401);
    });

    it('fails when flipping bit in byte 32 (S component boundary)', async () => {
      const kp = generateKeyPair();
      const { payload } = createSignedPayload(kp);
      const validSig = signReportPayload(payload, kp.secretKey);

      const sigBytes = parseSignature(validSig);
      sigBytes[32] ^= 0x01; // flip LSB of 33rd byte (scalar component)
      const flippedSig = formatSignature(sigBytes);

      const res = await validateAndSubmitReport(
        { ...payload, signature: flippedSig },
        { storage, now },
      );
      expect(res.success).toBe(false);
      if (res.success) return;

      expect(res.error.code).toBe('INVALID_SIGNATURE');
    });

    it('fails when flipping bit in byte 63 (last byte of signature)', async () => {
      const kp = generateKeyPair();
      const { payload } = createSignedPayload(kp);
      const validSig = signReportPayload(payload, kp.secretKey);

      const sigBytes = parseSignature(validSig);
      sigBytes[63] ^= 0x01; // flip LSB of last byte
      const flippedSig = formatSignature(sigBytes);

      const res = await validateAndSubmitReport(
        { ...payload, signature: flippedSig },
        { storage, now },
      );
      expect(res.success).toBe(false);
      if (res.success) return;

      expect(res.error.code).toBe('INVALID_SIGNATURE');
    });

    it('fails across multiple random byte positions (empirical sweep of 10 positions)', async () => {
      const kp = generateKeyPair();
      const { payload } = createSignedPayload(kp);
      const validSig = signReportPayload(payload, kp.secretKey);

      const positions = [3, 7, 12, 19, 27, 35, 42, 49, 56, 61];
      for (const pos of positions) {
        const sigBytes = parseSignature(validSig);
        sigBytes[pos] ^= 0x04;
        const flippedSig = formatSignature(sigBytes);

        const res = await validateAndSubmitReport(
          { ...payload, signature: flippedSig },
          { storage, now },
        );
        expect(res.success).toBe(false);
        if (!res.success) {
          expect(res.error.code).toBe('INVALID_SIGNATURE');
          expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(401);
        }
      }
    });

    it('rejects all-zeros signature (64 zero bytes) at schema validation stage due to base58 compression', async () => {
      const kp = generateKeyPair();
      const { payload } = createSignedPayload(kp);

      // In Base58, 64 zero bytes encode to 64 '1's, failing {86,88} length regex
      const allZeros = formatSignature(new Uint8Array(64).fill(0));
      const res = await validateAndSubmitReport(
        { ...payload, signature: allZeros },
        { storage, now },
      );
      expect(res.success).toBe(false);
      if (!res.success) {
        expect(res.error.code).toBe('INVALID_SCHEMA');
        expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(400);
      }
    });

    it('rejects arbitrary non-zero 64-byte forged signature with INVALID_SIGNATURE (401)', async () => {
      const kp = generateKeyPair();
      const { payload } = createSignedPayload(kp);

      // 64 bytes of 0xFF encodes to 87 base58 characters, satisfying schema regex
      const forged64Bytes = formatSignature(new Uint8Array(64).fill(0xff));
      const res = await validateAndSubmitReport(
        { ...payload, signature: forged64Bytes },
        { storage, now },
      );
      expect(res.success).toBe(false);
      if (!res.success) {
        expect(res.error.code).toBe('INVALID_SIGNATURE');
        expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(401);
      }
    });

    it('rejects truncated (63-byte) or overlong (65-byte) signature with schema validation error', async () => {
      const kp = generateKeyPair();
      const { payload } = createSignedPayload(kp);

      // 63-byte signature
      const shortSig = formatSignature(new Uint8Array(63).fill(1));
      const resShort = await validateAndSubmitReport(
        { ...payload, signature: shortSig },
        { storage, now },
      );
      expect(resShort.success).toBe(false);

      // Non-base58 characters (e.g. '0', 'O', 'I', 'l') in signature string
      const invalidBase58 = `ed25519:0OIl${'1'.repeat(84)}`;
      const resBase58 = await validateAndSubmitReport(
        { ...payload, signature: invalidBase58 },
        { storage, now },
      );
      expect(resBase58.success).toBe(false);
      if (!resBase58.success) {
        expect(resBase58.error.code).toBe('INVALID_SCHEMA');
        expect(getHttpStatusForIntakeErrorCode(resBase58.error.code)).toBe(400);
      }
    });
  });

  // =========================================================================
  // 4. EXPIRED TIMESTAMPS (expires_at <= now) THROW 400
  // =========================================================================
  describe('4. Expired Timestamps Boundary Validation (HTTP 400)', () => {
    it('rejects exact boundary expires_at === now with REPORT_EXPIRED (HTTP 400)', async () => {
      const kp = generateKeyPair();
      const { signedPayload } = createSignedPayload(kp, {
        issued_at: now - 60_000,
        expires_at: now, // EXACT boundary: expires_at === now
      });

      const res = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(res.success).toBe(false);
      if (res.success) return;

      expect(res.error.code).toBe('REPORT_EXPIRED');
      expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(400);

      // Verify submitReport throws IntakeException with 400
      await expect(submitReport(signedPayload, { storage, now })).rejects.toThrow(IntakeException);
      try {
        await submitReport(signedPayload, { storage, now });
      } catch (err) {
        expect(err).toBeInstanceOf(IntakeException);
        expect((err as IntakeException).code).toBe('REPORT_EXPIRED');
        expect((err as IntakeException).httpStatus).toBe(400);
      }
    });

    it('rejects expires_at === now - 1ms with REPORT_EXPIRED (HTTP 400)', async () => {
      const kp = generateKeyPair();
      const { signedPayload } = createSignedPayload(kp, {
        issued_at: now - 60_000,
        expires_at: now - 1, // expired by 1ms
      });

      const res = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(res.success).toBe(false);
      if (res.success) return;

      expect(res.error.code).toBe('REPORT_EXPIRED');
      expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(400);
    });

    it('rejects grossly expired report (expires_at = now - 86_400_000ms / 1 day ago) with 400', async () => {
      const kp = generateKeyPair();
      const { signedPayload } = createSignedPayload(kp, {
        issued_at: now - 90_000_000,
        expires_at: now - 86_400_000,
      });

      const res = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(res.success).toBe(false);
      if (res.success) return;

      expect(res.error.code).toBe('REPORT_EXPIRED');
      expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(400);
    });

    it('accepts report just above boundary: expires_at === now + 1ms', async () => {
      const kp = generateKeyPair();
      const { signedPayload } = createSignedPayload(kp, {
        issued_at: now - 1000,
        expires_at: now + 1, // Valid: strictly greater than now
      });

      const res = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(res.success).toBe(true);
      if (!res.success) return;
      expect(res.data.status).toBe('submitted');
    });

    it('rejects inverted temporal bounds expires_at === issued_at with EXPIRES_BEFORE_ISSUED (HTTP 400)', async () => {
      const kp = generateKeyPair();
      const payload: ReportSignablePayload = {
        network: 'testnet',
        accused_account_id: 'target.testnet',
        reporter_id: 'sentinel.testnet',
        reporter_public_key: kp.publicKey,
        category: 'drainer',
        description: 'Testing equal issued_at and expires_at boundary condition.',
        transaction_references: [],
        evidence_content_hashes: [],
        contract_code_hash: null,
        issued_at: now + 1000,
        expires_at: now + 1000, // Identical
        nonce: 'nonce-equal-bounds',
      };

      // Construct raw signature
      const serialized = serializeReportForSigning({
        ...payload,
        expires_at: payload.issued_at + 10,
      });
      const sig = signDetached(serialized, kp.secretKey);
      const rawPayload = { ...payload, signature: sig };

      const res = await validateAndSubmitReport(rawPayload, { storage, now });
      expect(res.success).toBe(false);
      if (res.success) return;

      expect(res.error.code).toBe('EXPIRES_BEFORE_ISSUED');
      expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(400);
    });

    it('rejects inverted temporal bounds expires_at < issued_at with EXPIRES_BEFORE_ISSUED (HTTP 400)', async () => {
      const kp = generateKeyPair();
      const payload: ReportSignablePayload = {
        network: 'testnet',
        accused_account_id: 'target.testnet',
        reporter_id: 'sentinel.testnet',
        reporter_public_key: kp.publicKey,
        category: 'drainer',
        description: 'Testing inverted issued_at and expires_at condition.',
        transaction_references: [],
        evidence_content_hashes: [],
        contract_code_hash: null,
        issued_at: now + 5000,
        expires_at: now + 2000, // Inverted
        nonce: 'nonce-inverted-bounds',
      };

      const serialized = serializeReportForSigning({
        ...payload,
        expires_at: payload.issued_at + 10,
      });
      const sig = signDetached(serialized, kp.secretKey);
      const rawPayload = { ...payload, signature: sig };

      const res = await validateAndSubmitReport(rawPayload, { storage, now });
      expect(res.success).toBe(false);
      if (res.success) return;

      expect(res.error.code).toBe('EXPIRES_BEFORE_ISSUED');
      expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(400);
    });
  });

  // =========================================================================
  // 5. FUTURE TIMESTAMPS (issued_at > now + 300_000ms) THROW 400
  // =========================================================================
  describe('5. Future Timestamp Clock Skew Validation (HTTP 400)', () => {
    it('accepts exact upper tolerance boundary: issued_at === now + 300_000ms', async () => {
      const kp = generateKeyPair();
      const { signedPayload } = createSignedPayload(kp, {
        issued_at: now + 300_000, // Exactly 5 minutes in future (tolerance boundary)
        expires_at: now + 600_000,
      });

      const res = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(res.success).toBe(true);
      if (!res.success) return;
      expect(res.data.status).toBe('submitted');
    });

    it('rejects boundary violation: issued_at === now + 300_001ms with ISSUED_IN_FUTURE (HTTP 400)', async () => {
      const kp = generateKeyPair();
      const { signedPayload } = createSignedPayload(kp, {
        issued_at: now + 300_001, // 1ms beyond 300_000ms tolerance
        expires_at: now + 600_000,
      });

      const res = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(res.success).toBe(false);
      if (res.success) return;

      expect(res.error.code).toBe('ISSUED_IN_FUTURE');
      expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(400);

      // Verify submitReport throws IntakeException with 400
      await expect(submitReport(signedPayload, { storage, now })).rejects.toThrow(IntakeException);
      try {
        await submitReport(signedPayload, { storage, now });
      } catch (err) {
        expect(err).toBeInstanceOf(IntakeException);
        expect((err as IntakeException).code).toBe('ISSUED_IN_FUTURE');
        expect((err as IntakeException).httpStatus).toBe(400);
      }
    });

    it('rejects extreme future timestamp: issued_at === now + 86_400_000ms (1 day in future) with 400', async () => {
      const kp = generateKeyPair();
      const { signedPayload } = createSignedPayload(kp, {
        issued_at: now + 86_400_000,
        expires_at: now + 90_000_000,
      });

      const res = await validateAndSubmitReport(signedPayload, { storage, now });
      expect(res.success).toBe(false);
      if (res.success) return;

      expect(res.error.code).toBe('ISSUED_IN_FUTURE');
      expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(400);
    });

    it('respects custom clockSkewToleranceMs (e.g. 10_000ms)', async () => {
      const kp = generateKeyPair();
      const customTolerance = 10_000;

      // Within custom tolerance
      const { signedPayload: validPayload } = createSignedPayload(kp, {
        issued_at: now + 10_000,
        expires_at: now + 50_000,
      });
      const resValid = await validateAndSubmitReport(validPayload, {
        storage,
        now,
        clockSkewToleranceMs: customTolerance,
      });
      expect(resValid.success).toBe(true);

      // 1ms beyond custom tolerance
      const { signedPayload: invalidPayload } = createSignedPayload(kp, {
        issued_at: now + 10_001,
        expires_at: now + 50_000,
      });
      const resInvalid = await validateAndSubmitReport(invalidPayload, {
        storage,
        now,
        clockSkewToleranceMs: customTolerance,
      });
      expect(resInvalid.success).toBe(false);
      if (!resInvalid.success) {
        expect(resInvalid.error.code).toBe('ISSUED_IN_FUTURE');
        expect(getHttpStatusForIntakeErrorCode(resInvalid.error.code)).toBe(400);
      }
    });

    it('rejects negative or zero issued_at with INVALID_SCHEMA (HTTP 400)', async () => {
      const kp = generateKeyPair();
      const { signedPayload } = createSignedPayload(kp);

      const resNegative = await validateAndSubmitReport(
        { ...signedPayload, issued_at: -100 },
        { storage, now },
      );
      expect(resNegative.success).toBe(false);
      if (!resNegative.success) {
        expect(resNegative.error.code).toBe('INVALID_SCHEMA');
        expect(getHttpStatusForIntakeErrorCode(resNegative.error.code)).toBe(400);
      }

      const resZero = await validateAndSubmitReport(
        { ...signedPayload, issued_at: 0 },
        { storage, now },
      );
      expect(resZero.success).toBe(false);
      if (!resZero.success) {
        expect(resZero.error.code).toBe('INVALID_SCHEMA');
      }
    });
  });

  // =========================================================================
  // 6. KEY SUBSTITUTION ATTACKS THROW 403
  // =========================================================================
  describe('6. Key Substitution & Reporter Impersonation Attacks (HTTP 403)', () => {
    it('throws IntakeException with HTTP 403 and code REPORTER_KEY_MISMATCH when attacker uses different key for registered reporter', async () => {
      const legitimateKp = generateKeyPair();
      const attackerKp = generateKeyPair();
      const victimReporterId = 'legitimate-auditor.testnet';

      // 1. Legitimate reporter submits first report
      const { signedPayload: legitPayload } = createSignedPayload(legitimateKp, {
        reporter_id: victimReporterId,
        nonce: 'legit-nonce-001',
      });
      const initial = await submitReport(legitPayload, { storage, now });
      expect(initial.status).toBe('submitted');

      // 2. Attacker crafts report claiming to be victimReporterId, signed with attacker's own key
      const { signedPayload: attackPayload } = createSignedPayload(attackerKp, {
        reporter_id: victimReporterId,
        nonce: 'attack-nonce-001',
      });

      // 3. Must be rejected with HTTP 403 REPORTER_KEY_MISMATCH
      let caughtError: unknown;
      try {
        await submitReport(attackPayload, { storage, now });
      } catch (err) {
        caughtError = err;
      }

      expect(caughtError).toBeInstanceOf(IntakeException);
      const intakeEx = caughtError as IntakeException;
      expect(intakeEx.code).toBe('REPORTER_KEY_MISMATCH');
      expect(intakeEx.httpStatus).toBe(403);
      expect(getHttpStatusForIntakeErrorCode(intakeEx.code)).toBe(403);
    });

    it('returns validation error with REPORTER_KEY_MISMATCH (403) via validateAndSubmitReport', async () => {
      const legitimateKp = generateKeyPair();
      const attackerKp = generateKeyPair();
      const victimReporterId = 'registered-auditor.testnet';

      await storage.registerReporter({
        reporter_id: victimReporterId,
        public_key: legitimateKp.publicKey,
        created_at: now - 5000,
      });

      const { signedPayload: attackPayload } = createSignedPayload(attackerKp, {
        reporter_id: victimReporterId,
      });

      const res = await validateAndSubmitReport(attackPayload, { storage, now });
      expect(res.success).toBe(false);
      if (res.success) return;

      expect(res.error.code).toBe('REPORTER_KEY_MISMATCH');
      expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(403);
    });

    it('enforces key immutability under real SQLite ReportRepository', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const kp1 = generateKeyPair();
      const kp2 = generateKeyPair();
      const reporterId = 'sqlite-auditor.testnet';

      // First submission registers kp1
      const { signedPayload: firstPayload } = createSignedPayload(kp1, {
        reporter_id: reporterId,
        nonce: 'sqlite-first-nonce',
      });
      const res1 = await submitReport(firstPayload, { storage: repo, now });
      expect(res1.status).toBe('submitted');

      // Second submission using kp2 for same reporterId fails with 403
      const { signedPayload: secondPayload } = createSignedPayload(kp2, {
        reporter_id: reporterId,
        nonce: 'sqlite-second-nonce',
      });

      const res2 = await validateAndSubmitReport(secondPayload, { storage: repo, now });
      expect(res2.success).toBe(false);
      if (res2.success) return;

      expect(res2.error.code).toBe('REPORTER_KEY_MISMATCH');
      expect(getHttpStatusForIntakeErrorCode(res2.error.code)).toBe(403);

      await expect(submitReport(secondPayload, { storage: repo, now })).rejects.toThrow(
        IntakeException,
      );
    });

    it('rejects attacker reusing victim public key with invalid attacker signature (fails signature check 401)', async () => {
      const legitimateKp = generateKeyPair();
      const attackerKp = generateKeyPair();

      const { payload } = createSignedPayload(legitimateKp);
      // Attacker signs payload with their own secret key, but leaves legitimateKp in reporter_public_key
      const forgedSig = signReportPayload(payload, attackerKp.secretKey);
      const attackPayload = { ...payload, signature: forgedSig };

      const res = await validateAndSubmitReport(attackPayload, { storage, now });
      expect(res.success).toBe(false);
      if (res.success) return;

      expect(res.error.code).toBe('INVALID_SIGNATURE');
      expect(getHttpStatusForIntakeErrorCode(res.error.code)).toBe(401);
    });
  });

  // =========================================================================
  // 7. STORAGE BOUNDARY & SQLITE INTEGRITY STRESS
  // =========================================================================
  describe('7. Storage Layer Stress & Database Invariants (src/storage/)', () => {
    it('executes migrations idempotently across repeated runs without error', () => {
      const db = createDatabase({ path: ':memory:' });
      const firstRun = runMigrations(db);
      expect(firstRun.length).toBe(4);

      for (let i = 0; i < 5; i++) {
        const nextRun = runMigrations(db);
        expect(nextRun).toEqual([]);
      }
    });

    it('enforces SQLite foreign key constraints when inserting report with unregistered reporter', () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);

      expect(() => {
        db.prepare(`
          INSERT INTO reports (
            report_id, network, accused_account_id, reporter_id, reporter_public_key,
            category, description, status, issued_at, expires_at, nonce, signature,
            created_at, updated_at
          ) VALUES (
            'rep-missing-reporter', 'testnet', 'target.testnet', 'unregistered.testnet',
            'ed25519:1111111111111111111111111111111111111111111', 'drainer',
            'valid description text min 10', 'submitted', 1000, 2000, 'nonce-fk-1', 'sig',
            1000, 1000
          )
        `).run();
      }).toThrow(/FOREIGN KEY constraint failed/i);
    });

    it('enforces SQLite CHECK constraint chk_report_expiry (expires_at > issued_at)', () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      repo.registerReporter({
        reporter_id: 'reporter-check.testnet',
        public_key: 'ed25519:1111111111111111111111111111111111111111111',
      });

      // Insert directly violating expires_at > issued_at
      expect(() => {
        db.prepare(`
          INSERT INTO reports (
            report_id, network, accused_account_id, reporter_id, reporter_public_key,
            category, description, status, issued_at, expires_at, nonce, signature,
            created_at, updated_at
          ) VALUES (
            'rep-invalid-check', 'testnet', 'target.testnet', 'reporter-check.testnet',
            'ed25519:1111111111111111111111111111111111111111111', 'drainer',
            'valid description text min 10', 'submitted', 2000, 1000, 'nonce-chk', 'sig',
            1000, 1000
          )
        `).run();
      }).toThrow(/CHECK constraint failed/i);
    });

    it('strictly maintains monotonic revision numbers on active block creation and revocation', () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      expect(repo.getLatestBlocklistRevision()).toBe(0);

      // Block 1
      const b1 = repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'bad-actor-1.testnet',
        scope: 'account',
        reason: 'Exploit confirmed',
        reviewer_id: 'rev-01',
      });
      expect(b1.blocklist_revision).toBe(1);
      expect(repo.getLatestBlocklistRevision()).toBe(1);

      // Block 2
      const b2 = repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'bad-actor-2.testnet',
        scope: 'account',
        reason: 'Exploit confirmed 2',
        reviewer_id: 'rev-01',
      });
      expect(b2.blocklist_revision).toBe(2);
      expect(repo.getLatestBlocklistRevision()).toBe(2);

      // Revoke Block 1
      const revRev = repo.revokeActiveBlock(b1.entry_id, {
        reviewer_id: 'rev-02',
        reason: 'False alarm resolved',
      });
      expect(revRev).toBe(3);
      expect(repo.getLatestBlocklistRevision()).toBe(3);

      const revList = repo.getBlocklistRevisions(10);
      expect(revList.map((r) => r.revision_number)).toEqual([3, 2, 1]);
    });

    it('resists SQL injection payloads in account IDs, descriptions, and nonces', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const kp = generateKeyPair();
      const sqliPayloads = [
        "target.testnet'; DROP TABLE reports; --",
        "' OR '1'='1",
        "admin'--",
        'test"; DROP TABLE reporters; --',
      ];

      for (let i = 0; i < sqliPayloads.length; i++) {
        const sqli = sqliPayloads[i];
        const { signedPayload } = createSignedPayload(kp, {
          reporter_id: `auditor-sqli-${i}.testnet`,
          description: `Attempting injection: ${sqli}`,
          nonce: `nonce-${i}-${sqli.replace(/[^a-zA-Z0-9]/g, '_')}`,
        });

        const res = await validateAndSubmitReport(signedPayload, { storage: repo, now });
        expect(res.success).toBe(true);
        if (!res.success) return;

        // Verify database tables are intact and uncorrupted
        const check = db.prepare('SELECT COUNT(*) as count FROM reports').get() as {
          count: number;
        };
        expect(check.count).toBe(i + 1);
      }
    });

    it('safely handles unicode, special characters, and emojis in report contents', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const kp = generateKeyPair();
      const unicodeDesc = '🚨 CRITICAL EXPLOIT DETECTED: 0xDEADBEEF 💀 詐欺 ⚠️';
      const { signedPayload } = createSignedPayload(kp, {
        description: unicodeDesc,
      });

      const res = await validateAndSubmitReport(signedPayload, { storage: repo, now });
      expect(res.success).toBe(true);
      if (!res.success) return;

      const stored = repo.getReport(res.data.report_id);
      expect(stored?.description).toBe(unicodeDesc);
    });
  });
});
