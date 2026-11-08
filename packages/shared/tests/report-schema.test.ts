import { describe, expect, it } from 'vitest';
import { generateKeyPair, signDetached } from '../src/crypto/ed25519.js';
import {
  DependenceGroupSummarySchema,
  GetReportResponseSchema,
  ReceiverReportsResponseSchema,
  ReceiverReputationSchema,
  ReportDetailResponseSchema,
  ReportReviewResponseSchema,
  ReportSubmitResponseSchema,
  ReportSummarySchema,
  ReviewReportRequestSchema,
  ReviewReportResponseSchema,
  SubmitReportRequestSchema,
  SubmitReportResponseSchema,
} from '../src/schemas/report.js';

describe('Report Schema Validation', () => {
  const kp = generateKeyPair();
  const sampleSig = signDetached(new Uint8Array(32), kp.secretKey);

  const validReportBase = {
    network: 'testnet' as const,
    accused_account_id: 'malicious-receiver.testnet',
    reporter_id: 'honest-reporter.testnet',
    reporter_public_key: kp.publicKey,
    category: 'drainer' as const,
    description: 'Drained 15 NEAR from treasury using an unauthorized re-entrancy call.',
    transaction_references: ['9ZpQK81M2w2m5bN6o7p8q9r0s1t2u3v4w5x6y7z8a9b0c'],
    evidence_content_hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    contract_code_hash: '1111111111111111111111111111111111111111111111111111111111111111',
    issued_at: 1700000000000,
    expires_at: 1700604800000,
    nonce: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    signature: sampleSig,
  };

  it('validates a correct, fully-formed report payload', () => {
    const result = SubmitReportRequestSchema.safeParse(validReportBase);
    expect(result.success).toBe(true);
  });

  it('validates minimal report with defaults for references and evidence', () => {
    const minimal = {
      network: 'sandbox' as const,
      accused_account_id: 'receiver.sandbox',
      reporter_id: 'reporter.sandbox',
      reporter_public_key: kp.publicKey,
      category: 'phishing' as const,
      description: 'Phishing domain impersonating legitimate bridge.',
      issued_at: 1700000000000,
      expires_at: 1700100000000,
      nonce: 'nonce-12345',
      signature: sampleSig,
    };
    const result = SubmitReportRequestSchema.safeParse(minimal);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.transaction_references).toEqual([]);
      expect(result.data.evidence_content_hashes).toEqual([]);
    }
  });

  it('rejects invalid network identifier', () => {
    const result = SubmitReportRequestSchema.safeParse({
      ...validReportBase,
      network: 'ethereum',
    });
    expect(result.success).toBe(false);
  });

  it('rejects malformed reporter public keys', () => {
    const badKeys = [
      'secp256k1:6E8sCci9badyRkXb3JoRpAx5bMrqZ82ozzC2hi7qENJv', // Wrong algorithm
      '6E8sCci9badyRkXb3JoRpAx5bMrqZ82ozzC2hi7qENJv', // Missing ed25519: prefix
      'ed25519:short', // Too short
      'ed25519:0OIlInvalidBase58CharactersAreNotAllowedInNear', // Invalid Base58 chars (0, O, I, l)
    ];
    for (const pk of badKeys) {
      const res = SubmitReportRequestSchema.safeParse({
        ...validReportBase,
        reporter_public_key: pk,
      });
      expect(res.success).toBe(false);
    }
  });

  it('rejects unsupported report category', () => {
    const result = SubmitReportRequestSchema.safeParse({
      ...validReportBase,
      category: 'spam',
    });
    expect(result.success).toBe(false);
  });

  it('enforces description length constraints (10 to 1000 characters)', () => {
    const tooShort = SubmitReportRequestSchema.safeParse({
      ...validReportBase,
      description: 'Too short',
    });
    expect(tooShort.success).toBe(false);

    const tooLong = SubmitReportRequestSchema.safeParse({
      ...validReportBase,
      description: 'x'.repeat(1001),
    });
    expect(tooLong.success).toBe(false);
  });

  it('enforces maximum transaction references (max 20)', () => {
    const oversizedRefs = Array.from(
      { length: 21 },
      (_, i) => `tx_reference_hash_${i.toString().padStart(10, '0')}`,
    );
    const result = SubmitReportRequestSchema.safeParse({
      ...validReportBase,
      transaction_references: oversizedRefs,
    });
    expect(result.success).toBe(false);
  });

  it('enforces maximum evidence content hashes (max 10)', () => {
    const oversizedHashes = Array.from({ length: 11 }, () => 'a'.repeat(64));
    const result = SubmitReportRequestSchema.safeParse({
      ...validReportBase,
      evidence_content_hashes: oversizedHashes,
    });
    expect(result.success).toBe(false);
  });

  it('enforces strict temporal ordering: expires_at must be strictly greater than issued_at', () => {
    const invertedTimes = SubmitReportRequestSchema.safeParse({
      ...validReportBase,
      issued_at: 1700604800000,
      expires_at: 1700000000000,
    });
    expect(invertedTimes.success).toBe(false);

    const identicalTimes = SubmitReportRequestSchema.safeParse({
      ...validReportBase,
      issued_at: 1700000000000,
      expires_at: 1700000000000,
    });
    expect(identicalTimes.success).toBe(false);
  });

  it('rejects empty or whitespace nonce', () => {
    const emptyNonce = SubmitReportRequestSchema.safeParse({
      ...validReportBase,
      nonce: '',
    });
    expect(emptyNonce.success).toBe(false);
  });

  it('validates reviewer report request schema with mandatory audit reason', () => {
    const validReview = {
      decision: 'active_block' as const,
      scope: 'both' as const,
      reason: 'Confirmed drainer behavior verified via on-chain transaction trace 9ZpQ...',
      block_expires_at: 1731500000000,
    };
    const res = ReviewReportRequestSchema.safeParse(validReview);
    expect(res.success).toBe(true);

    // Empty reason must fail auditability invariant
    const missingReason = ReviewReportRequestSchema.safeParse({
      decision: 'active_block',
      scope: 'account',
      reason: '',
    });
    expect(missingReason.success).toBe(false);
  });

  it('validates SubmitReportResponseSchema and ReportSubmitResponseSchema', () => {
    const validResponse = {
      report_id: 'a0000000-0000-0000-0000-000000000001',
      status: 'submitted' as const,
      issued_at: 1700000000000,
      expires_at: 1700600000000,
    };
    expect(SubmitReportResponseSchema.safeParse(validResponse).success).toBe(true);
    expect(ReportSubmitResponseSchema.safeParse(validResponse).success).toBe(true);

    const badStatus = { ...validResponse, status: 'reviewed' };
    expect(SubmitReportResponseSchema.safeParse(badStatus).success).toBe(false);

    const badUuid = { ...validResponse, report_id: 'not-a-uuid' };
    expect(SubmitReportResponseSchema.safeParse(badUuid).success).toBe(false);
  });

  it('validates ReviewReportResponseSchema and ReportReviewResponseSchema', () => {
    const validReviewResp = {
      review_id: 'b0000000-0000-0000-0000-000000000002',
      status: 'reviewed',
      blocklist_revision: 5,
    };
    expect(ReviewReportResponseSchema.safeParse(validReviewResp).success).toBe(true);
    expect(ReportReviewResponseSchema.safeParse(validReviewResp).success).toBe(true);

    const negativeRevision = { ...validReviewResp, blocklist_revision: -1 };
    expect(ReviewReportResponseSchema.safeParse(negativeRevision).success).toBe(false);
  });

  it('validates GetReportResponseSchema and ReportDetailResponseSchema', () => {
    const validDetailResp = {
      report: {
        report_id: 'c0000000-0000-0000-0000-000000000003',
        network: 'testnet' as const,
        accused_account_id: 'drainer.testnet',
        reporter_id: 'reporter.testnet',
        reporter_public_key: kp.publicKey,
        category: 'drainer' as const,
        description: 'Detailed report description meeting character length requirements.',
        transaction_references: ['tx-hash-1234567890'],
        evidence_content_hashes: [
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        ],
        status: 'reviewed' as const,
        issued_at: 1700000000000,
        expires_at: 1700600000000,
        nonce: 'nonce-uuid-123',
        signature: sampleSig,
        created_at: 1700000001000,
      },
      review_history: [
        {
          review_id: 'd0000000-0000-0000-0000-000000000004',
          report_id: 'c0000000-0000-0000-0000-000000000003',
          reviewer_id: 'reviewer.testnet',
          status: 'reviewed' as const,
          decision: 'active_block' as const,
          scope: 'account' as const,
          reason: 'Verified drainer account from on-chain trace.',
          blocklist_entry_id: 'block-entry-1',
          blocklist_revision: 3,
          reviewed_at: 1700000500000,
        },
      ],
      dependence_group: {
        groupId: 'grp-001',
        reporterCount: 3,
        effectiveWeight: 1.0,
        commonFunderId: 'funder.testnet',
        faucetExempted: false,
      },
    };

    expect(GetReportResponseSchema.safeParse(validDetailResp).success).toBe(true);
    expect(ReportDetailResponseSchema.safeParse(validDetailResp).success).toBe(true);
  });

  it('validates ReceiverReportsResponseSchema', () => {
    const validReceiverReports = {
      is_blocked: true,
      total_reports: 2,
      effective_weight: 1.0,
      reports: [
        {
          report_id: 'e0000000-0000-0000-0000-000000000005',
          reporter_id: 'reporter1.testnet',
          category: 'phishing' as const,
          status: 'reviewed' as const,
          issued_at: 1700000000000,
          effective_weight: 0.5,
          dependence_group_id: 'grp-001',
        },
      ],
      dependence_groups: [
        {
          groupId: 'grp-001',
          reporterCount: 2,
          effectiveWeight: 1.0,
          commonFunderId: 'sybil-funder.testnet',
          faucetExempted: false,
        },
      ],
    };
    expect(ReceiverReportsResponseSchema.safeParse(validReceiverReports).success).toBe(true);
  });

  it('validates ReceiverReputationSchema according to interface contract', () => {
    const validReputation = {
      isBlocked: false,
      blockReason: undefined,
      blocklistRevision: 7,
      rawReportCount: 4,
      effectiveReportWeight: 1.0,
      unresolvedReportsCount: 2,
      circularActivityDetected: true,
      circularActivityScore: 45,
      dependenceGroups: [
        {
          groupId: 'grp-1',
          reporterCount: 3,
          effectiveWeight: 1.0,
          commonFunderId: 'faucet.testnet',
          faucetExempted: true,
        },
      ],
      graphCoverage: {
        accountsVisited: 42,
        edgesTraversed: 118,
        truncated: false,
        windowDays: 7,
      },
      reputationRiskPoints: 60,
      reasonCodes: ['CIRCULAR_ACTIVITY', 'COMMON_FAUCET_EXEMPTED'],
    };
    const res = ReceiverReputationSchema.safeParse(validReputation);
    expect(res.success).toBe(true);

    // Score bounds check
    const invalidScore = { ...validReputation, circularActivityScore: 105 };
    expect(ReceiverReputationSchema.safeParse(invalidScore).success).toBe(false);

    const invalidRisk = { ...validReputation, reputationRiskPoints: -5 };
    expect(ReceiverReputationSchema.safeParse(invalidRisk).success).toBe(false);
  });
});
