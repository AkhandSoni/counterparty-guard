import bs58 from 'bs58';

import { describe, expect, it } from 'vitest';
import {
  formatSignature,
  generateKeyPair,
  parsePublicKey,
  parseSignature,
  signDetached,
  verifyDetached,
} from '../src/crypto/ed25519.js';
import {
  REPORT_DOMAIN_SEPARATOR,
  type ReportSignablePayload,
  serializeReportForSigning,
  signReportPayload,
  verifyReportSignature,
} from '../src/crypto/report-signing.js';
import {
  CheckResponseSchema,
} from '../src/schemas/check.js';
import {
  ReceiverReputationSchema,
  type SubmitReportRequest,
  SubmitReportRequestSchema,
} from '../src/schemas/report.js';
import '../src/schemas/scenario.js';

describe('Adversarial Challenge & Stress Tests', () => {
  const kp = generateKeyPair();
  const sampleMsg = new Uint8Array([1, 2, 3, 4, 5]);
  const sampleSig = signDetached(sampleMsg, kp.secretKey);

  const baseReport = {
    network: 'testnet' as const,
    accused_account_id: 'bad-receiver.testnet',
    reporter_id: 'reporter-alpha.testnet',
    reporter_public_key: kp.publicKey,
    category: 'drainer' as const,
    description: 'Valid description that has sufficient length over 10 chars.',
    transaction_references: ['9XyZ1234567890abcdef'],
    evidence_content_hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    contract_code_hash: null,
    issued_at: 1700000000000,
    expires_at: 1700604800000,
    nonce: 'unique-nonce-001',
    signature: sampleSig,
  };

  describe('1. Malformed Base58 Keys & Signatures', () => {
    it('rejects keys and signatures with invalid Base58 characters (0, O, I, l, spaces, symbols)', () => {
      const invalidChars = ['0', 'O', 'I', 'l', ' ', '!', '@', '#', '$', '%', '^', '&', '*'];
      for (const char of invalidChars) {
        const badPk = `ed25519:1111111111111111111111111111111111111111111${char}`;
        expect(
          SubmitReportRequestSchema.safeParse({ ...baseReport, reporter_public_key: badPk })
            .success,
        ).toBe(false);

        const badSig = `ed25519:${'1'.repeat(87)}${char}`;
        expect(
          SubmitReportRequestSchema.safeParse({ ...baseReport, signature: badSig }).success,
        ).toBe(false);
      }
    });

    it('rejects truncated and oversized public key strings in parsePublicKey and schema', () => {
      // 31 bytes encoded in base58
      const raw31 = new Uint8Array(31);
      const pk31 = `ed25519:${bs58.encode(raw31)}`;
      expect(() => parsePublicKey(pk31)).toThrow(/Invalid Ed25519 public key byte length/);
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, reporter_public_key: pk31 }).success,
      ).toBe(false);

      // 33 bytes encoded in base58
      const raw33 = new Uint8Array(33);
      const pk33 = `ed25519:${bs58.encode(raw33)}`;
      expect(() => parsePublicKey(pk33)).toThrow(/Invalid Ed25519 public key byte length/);
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, reporter_public_key: pk33 }).success,
      ).toBe(false);

      // 0 bytes
      const pk0 = 'ed25519:';
      expect(() => parsePublicKey(pk0)).toThrow();
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, reporter_public_key: pk0 }).success,
      ).toBe(false);
    });

    it('rejects truncated and oversized signature strings in parseSignature and schema', () => {
      // 63 bytes
      const raw63 = new Uint8Array(63);
      const sig63 = `ed25519:${bs58.encode(raw63)}`;
      expect(() => parseSignature(sig63)).toThrow(/Invalid Ed25519 signature byte length/);
      expect(SubmitReportRequestSchema.safeParse({ ...baseReport, signature: sig63 }).success).toBe(
        false,
      );

      // 65 bytes
      const raw65 = new Uint8Array(65);
      const sig65 = `ed25519:${bs58.encode(raw65)}`;
      expect(() => parseSignature(sig65)).toThrow(/Invalid Ed25519 signature byte length/);
      expect(SubmitReportRequestSchema.safeParse({ ...baseReport, signature: sig65 }).success).toBe(
        false,
      );
    });

    it('handles verifyDetached safely with completely invalid or malformed strings without throwing', () => {
      expect(verifyDetached(sampleMsg, 'not-a-sig', kp.publicKey)).toBe(false);
      expect(verifyDetached(sampleMsg, sampleSig, 'not-a-pk')).toBe(false);
      expect(verifyDetached(sampleMsg, '', '')).toBe(false);
      expect(verifyDetached(sampleMsg, 'ed25519:0000000000', kp.publicKey)).toBe(false);
    });

    it('rejects bit-flipped or mutated signatures on otherwise valid report', () => {
      const validPayload: ReportSignablePayload = {
        ...baseReport,
        reporter_public_key: kp.publicKey,
      };
      const validSig = signReportPayload(validPayload, kp.secretKey);
      const sigBytes = parseSignature(validSig);

      // Flip a bit in the signature
      sigBytes[10] ^= 0x01;
      const mutatedSig = formatSignature(sigBytes);

      const reportWithMutatedSig = {
        ...validPayload,
        signature: mutatedSig,
      };
      expect(verifyReportSignature(reportWithMutatedSig)).toBe(false);
    });

    it('evaluates base58 byte length anomaly: 43 ones matches schema regex but fails byte length validation in parsePublicKey', () => {
      // 43 ones: matches regex ^ed25519:[1-9A-HJ-NP-Za-km-z]{43,44}$
      const pk43Ones = `ed25519:${'1'.repeat(43)}`;
      // Schema regex passes:
      const schemaResult = SubmitReportRequestSchema.safeParse({
        ...baseReport,
        reporter_public_key: pk43Ones,
      });
      expect(schemaResult.success).toBe(true);

      // However, bs58 decodes 43 ones to 43 bytes (not 32 bytes):
      expect(() => parsePublicKey(pk43Ones)).toThrow(
        /Invalid Ed25519 public key byte length: expected 32, got 43/,
      );

      // Cryptographic verification safely catches it and returns false:
      expect(verifyReportSignature({ ...baseReport, reporter_public_key: pk43Ones })).toBe(false);
    });
  });

  describe('2. Temporal Edge Cases', () => {
    it('rejects expiry < issued_at in SubmitReportRequestSchema', () => {
      const res = SubmitReportRequestSchema.safeParse({
        ...baseReport,
        issued_at: 1700604800000,
        expires_at: 1700000000000,
      });
      expect(res.success).toBe(false);
      if (!res.success) {
        expect(res.error.issues[0].message).toContain(
          'expires_at must be strictly greater than issued_at',
        );
      }
    });

    it('rejects expiry == issued_at (expires_at = now edge case) in SubmitReportRequestSchema and verifyReportSignature', () => {
      const now = 1700000000000;
      const res = SubmitReportRequestSchema.safeParse({
        ...baseReport,
        issued_at: now,
        expires_at: now,
      });
      expect(res.success).toBe(false);

      const reportSameTime = {
        ...baseReport,
        issued_at: now,
        expires_at: now,
      };
      expect(verifyReportSignature(reportSameTime)).toBe(false);
    });

    it('rejects zero or negative timestamps in SubmitReportRequestSchema', () => {
      expect(SubmitReportRequestSchema.safeParse({ ...baseReport, issued_at: 0 }).success).toBe(
        false,
      );
      expect(SubmitReportRequestSchema.safeParse({ ...baseReport, issued_at: -1000 }).success).toBe(
        false,
      );
      expect(SubmitReportRequestSchema.safeParse({ ...baseReport, expires_at: 0 }).success).toBe(
        false,
      );
      expect(SubmitReportRequestSchema.safeParse({ ...baseReport, expires_at: -500 }).success).toBe(
        false,
      );
    });

    it('rejects non-integer floating-point timestamps in SubmitReportRequestSchema', () => {
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, issued_at: 1700000000.123 }).success,
      ).toBe(false);
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, expires_at: 1700604800.999 }).success,
      ).toBe(false);
    });

    it('handles large u64 timestamps without serialization failure in Borsh', () => {
      const largeTime = 1800000000000;
      const payload: ReportSignablePayload = {
        ...baseReport,
        issued_at: largeTime,
        expires_at: largeTime + 86400000,
      };
      const serialized = serializeReportForSigning(payload);
      expect(serialized).toBeInstanceOf(Uint8Array);
      expect(serialized.length).toBeGreaterThan(0);
    });
  });

  describe('3. String Boundaries, Oversized Payloads & Negative Values', () => {
    it('rejects zero-length and undersized (<10 chars) descriptions', () => {
      expect(SubmitReportRequestSchema.safeParse({ ...baseReport, description: '' }).success).toBe(
        false,
      );
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, description: 'short' }).success,
      ).toBe(false);
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, description: '123456789' }).success,
      ).toBe(false);
      // exactly 10 characters is allowed
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, description: '1234567890' }).success,
      ).toBe(true);
    });

    it('rejects oversized descriptions (>1000 chars, including >2000 chars)', () => {
      // 1001 chars
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, description: 'A'.repeat(1001) })
          .success,
      ).toBe(false);

      // 2000 chars
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, description: 'B'.repeat(2000) })
          .success,
      ).toBe(false);

      // 2500 chars
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, description: 'C'.repeat(2500) })
          .success,
      ).toBe(false);

      // Exactly 1000 chars is valid
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, description: 'D'.repeat(1000) })
          .success,
      ).toBe(true);
    });

    it('rejects zero-length and oversized account IDs and nonces in SubmitReportRequestSchema', () => {
      // accused_account_id: min 2, max 64
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, accused_account_id: '' }).success,
      ).toBe(false);
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, accused_account_id: 'a' }).success,
      ).toBe(false);
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, accused_account_id: 'a'.repeat(65) })
          .success,
      ).toBe(false);

      // reporter_id: min 2, max 64
      expect(SubmitReportRequestSchema.safeParse({ ...baseReport, reporter_id: '' }).success).toBe(
        false,
      );
      expect(SubmitReportRequestSchema.safeParse({ ...baseReport, reporter_id: 'x' }).success).toBe(
        false,
      );
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, reporter_id: 'x'.repeat(65) }).success,
      ).toBe(false);

      // nonce: min 1, max 64
      expect(SubmitReportRequestSchema.safeParse({ ...baseReport, nonce: '' }).success).toBe(false);
      expect(
        SubmitReportRequestSchema.safeParse({ ...baseReport, nonce: 'n'.repeat(65) }).success,
      ).toBe(false);
    });

    it('rejects negative numbers across response and reputation models', () => {
      const validReputation = {
        isBlocked: false,
        blocklistRevision: 1,
        rawReportCount: 2,
        effectiveReportWeight: 1.0,
        unresolvedReportsCount: 1,
        circularActivityDetected: false,
        circularActivityScore: 0,
        dependenceGroups: [],
        graphCoverage: {
          accountsVisited: 10,
          edgesTraversed: 20,
          truncated: false,
          windowDays: 7,
        },
        reputationRiskPoints: 25,
        reasonCodes: [],
      };

      // Negative circularActivityScore
      expect(
        ReceiverReputationSchema.safeParse({ ...validReputation, circularActivityScore: -1 })
          .success,
      ).toBe(false);

      // Negative reputationRiskPoints
      expect(
        ReceiverReputationSchema.safeParse({ ...validReputation, reputationRiskPoints: -1 })
          .success,
      ).toBe(false);

      // Negative blocklistRevision
      expect(
        ReceiverReputationSchema.safeParse({ ...validReputation, blocklistRevision: -1 }).success,
      ).toBe(false);

      // Negative rawReportCount
      expect(
        ReceiverReputationSchema.safeParse({ ...validReputation, rawReportCount: -1 }).success,
      ).toBe(false);

      // Negative effectiveReportWeight
      expect(
        ReceiverReputationSchema.safeParse({ ...validReputation, effectiveReportWeight: -0.5 })
          .success,
      ).toBe(false);

      // Negative graph coverage counts
      expect(
        ReceiverReputationSchema.safeParse({
          ...validReputation,
          graphCoverage: { ...validReputation.graphCoverage, accountsVisited: -5 },
        }).success,
      ).toBe(false);
    });
  });

  describe('4. Boundary Checks on Risk & Indicator Scores (0, 100, -1, 101)', () => {
    const validReputationBase = {
      isBlocked: false,
      blocklistRevision: 0,
      rawReportCount: 0,
      effectiveReportWeight: 0,
      unresolvedReportsCount: 0,
      circularActivityDetected: false,
      circularActivityScore: 0,
      dependenceGroups: [],
      graphCoverage: {
        accountsVisited: 0,
        edgesTraversed: 0,
        truncated: false,
        windowDays: 7,
      },
      reputationRiskPoints: 0,
      reasonCodes: [],
    };

    it('accepts exact lower boundary score 0 and upper boundary score 100', () => {
      // Score 0
      expect(
        ReceiverReputationSchema.safeParse({
          ...validReputationBase,
          circularActivityScore: 0,
          reputationRiskPoints: 0,
        }).success,
      ).toBe(true);

      // Score 100
      expect(
        ReceiverReputationSchema.safeParse({
          ...validReputationBase,
          circularActivityScore: 100,
          reputationRiskPoints: 100,
        }).success,
      ).toBe(true);
    });

    it('rejects below boundary score -1 and above boundary score 101', () => {
      // Score -1
      expect(
        ReceiverReputationSchema.safeParse({
          ...validReputationBase,
          circularActivityScore: -1,
        }).success,
      ).toBe(false);

      expect(
        ReceiverReputationSchema.safeParse({
          ...validReputationBase,
          reputationRiskPoints: -1,
        }).success,
      ).toBe(false);

      // Score 101
      expect(
        ReceiverReputationSchema.safeParse({
          ...validReputationBase,
          circularActivityScore: 101,
        }).success,
      ).toBe(false);

      expect(
        ReceiverReputationSchema.safeParse({
          ...validReputationBase,
          reputationRiskPoints: 101,
        }).success,
      ).toBe(false);
    });

    it('rejects fractional scores where integer is required (reputationRiskPoints and risk_indicator)', () => {
      expect(
        ReceiverReputationSchema.safeParse({
          ...validReputationBase,
          reputationRiskPoints: 50.5,
        }).success,
      ).toBe(false);

      // CheckResponse risk_indicator requires integer [0..100]
      const validCheckResponse = {
        check_id: 'a0000000-0000-0000-0000-000000000001',
        schema_version: 1,
        agent_id: 'agent.testnet',
        decision: 'allow' as const,
        risk_indicator: 0,
        reason_codes: [],
        reasons: [],
        evidence_refs: [],
        coverage: {
          accounts_visited: 1,
          edges_traversed: 0,
          truncated: false,
          window_days: 7,
        },
        source_mode: 'fixture' as const,
        evaluated_at: 1700000000000,
        expires_at: 1700000060000,
        policy_revision: 1,
        blocklist_revision: 1,
        permit: null,
        attestation: null,
      };

      expect(CheckResponseSchema.safeParse(validCheckResponse).success).toBe(true);
      expect(
        CheckResponseSchema.safeParse({ ...validCheckResponse, risk_indicator: -1 }).success,
      ).toBe(false);
      expect(
        CheckResponseSchema.safeParse({ ...validCheckResponse, risk_indicator: 101 }).success,
      ).toBe(false);
      expect(
        CheckResponseSchema.safeParse({ ...validCheckResponse, risk_indicator: 42.7 }).success,
      ).toBe(false);
    });

    it('rejects NaN, Infinity, -Infinity for risk scores', () => {
      expect(
        ReceiverReputationSchema.safeParse({
          ...validReputationBase,
          reputationRiskPoints: Number.NaN,
        }).success,
      ).toBe(false);
      expect(
        ReceiverReputationSchema.safeParse({
          ...validReputationBase,
          reputationRiskPoints: Number.POSITIVE_INFINITY,
        }).success,
      ).toBe(false);
      expect(
        ReceiverReputationSchema.safeParse({
          ...validReputationBase,
          reputationRiskPoints: Number.NEGATIVE_INFINITY,
        }).success,
      ).toBe(false);
    });
  });

  describe('5. Cross-Domain Signing Replay Resistance & Canonical Borsh Serialization', () => {
    it('verifies that canonical domain separator COUNTERPARTY_GUARD_REPORT_V1 is immutable and enforced', () => {
      expect(REPORT_DOMAIN_SEPARATOR).toBe('COUNTERPARTY_GUARD_REPORT_V1');

      const payload: ReportSignablePayload = {
        ...baseReport,
        reporter_public_key: kp.publicKey,
      };

      const legitimateSerialized = serializeReportForSigning(payload);
      const legitimateSig = signDetached(legitimateSerialized, kp.secretKey);

      expect(
        verifyReportSignature({
          ...payload,
          signature: legitimateSig,
        }),
      ).toBe(true);

      // Forged with permit domain
      const forgedPermitSerialized = serializeReportForSigning(
        payload,
        'COUNTERPARTY_GUARD_PERMIT_V1',
      );
      const forgedPermitSig = signDetached(forgedPermitSerialized, kp.secretKey);
      expect(
        verifyReportSignature({
          ...payload,
          signature: forgedPermitSig,
        }),
      ).toBe(false);

      // Forged with empty domain
      const forgedEmptySerialized = serializeReportForSigning(payload, '');
      const forgedEmptySig = signDetached(forgedEmptySerialized, kp.secretKey);
      expect(
        verifyReportSignature({
          ...payload,
          signature: forgedEmptySig,
        }),
      ).toBe(false);

      // Forged with similar domain (e.g. V2 or typo)
      const forgedV2Serialized = serializeReportForSigning(payload, 'COUNTERPARTY_GUARD_REPORT_V2');
      const forgedV2Sig = signDetached(forgedV2Serialized, kp.secretKey);
      expect(
        verifyReportSignature({
          ...payload,
          signature: forgedV2Sig,
        }),
      ).toBe(false);
    });

    it('ensures distinct payloads produce distinct Borsh serialized byte outputs (collision resistance)', () => {
      const payload1: ReportSignablePayload = {
        ...baseReport,
        reporter_public_key: kp.publicKey,
        nonce: 'nonce-1',
      };
      const payload2: ReportSignablePayload = {
        ...baseReport,
        reporter_public_key: kp.publicKey,
        nonce: 'nonce-2',
      };

      const bytes1 = serializeReportForSigning(payload1);
      const bytes2 = serializeReportForSigning(payload2);

      expect(bytes1).not.toEqual(bytes2);
    });

    it('ensures optional contract_code_hash serializes deterministically (null vs omitted)', () => {
      const payloadWithNull: ReportSignablePayload = {
        ...baseReport,
        reporter_public_key: kp.publicKey,
        contract_code_hash: null,
      };
      const payloadWithUndefined: ReportSignablePayload = {
        ...baseReport,
        reporter_public_key: kp.publicKey,
        contract_code_hash: undefined,
      };

      const bytesNull = serializeReportForSigning(payloadWithNull);
      const bytesUndefined = serializeReportForSigning(payloadWithUndefined);

      expect(bytesNull).toEqual(bytesUndefined);
    });
  });

  describe('6. Security Invariants & Robustness Against Crashes', () => {
    it('verifyReportSignature handles invalid public keys without crashing', () => {
      const payload: ReportSignablePayload = {
        ...baseReport,
        reporter_public_key: 'ed25519:invalid-key-short',
      };
      // Should return false and not throw uncaught error
      expect(verifyReportSignature({ ...payload, signature: sampleSig })).toBe(false);
    });

    it('verifyReportSignature handles invalid signature strings without crashing', () => {
      const payload: ReportSignablePayload = {
        ...baseReport,
        reporter_public_key: kp.publicKey,
      };
      expect(verifyReportSignature({ ...payload, signature: 'ed25519:broken-sig' })).toBe(false);
      expect(verifyReportSignature({ ...payload, signature: '' })).toBe(false);
    });

    it('verifyReportSignature returns false when expires_at <= issued_at even with valid signature', () => {
      const now = 1700000000000;
      const payload: ReportSignablePayload = {
        ...baseReport,
        reporter_public_key: kp.publicKey,
        issued_at: now,
        expires_at: now,
      };
      const sig = signReportPayload(payload, kp.secretKey);
      expect(verifyReportSignature({ ...payload, signature: sig })).toBe(false);
    });

    it('identifies unhandled exception risk: passing NaN timestamp directly into verifyReportSignature throws RangeError', () => {
      const unvalidatedPayload = {
        ...baseReport,
        issued_at: Number.NaN,
        expires_at: 1700604800000,
      } as unknown as SubmitReportRequest;
      // Shows that serializeReportForSigning throws RangeError because BigInt(NaN) fails
      expect(() => verifyReportSignature(unvalidatedPayload)).toThrow(RangeError);
    });
  });
});
