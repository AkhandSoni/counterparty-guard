import { z } from 'zod';

export const ReportCategorySchema = z.enum([
  'drainer',
  'phishing',
  'malicious_contract',
  'impersonation',
  'prompt_injection_source',
  'wash_trading',
  'other',
]);
export type ReportCategory = z.infer<typeof ReportCategorySchema>;

export const ReportStatusSchema = z.enum([
  'submitted',
  'references_verified',
  'corroborated',
  'reviewed',
  'rejected',
  'withdrawn',
  'expired',
]);
export type ReportStatus = z.infer<typeof ReportStatusSchema>;

export const SubmitReportRequestSchema = z
  .object({
    network: z.enum(['testnet', 'mainnet', 'sandbox']),
    accused_account_id: z.string().min(2).max(64),
    reporter_id: z.string().min(2).max(64),
    reporter_public_key: z.string().regex(/^ed25519:[1-9A-HJ-NP-Za-km-z]{43,44}$/),
    category: ReportCategorySchema,
    description: z.string().min(10).max(1000),
    transaction_references: z.array(z.string().min(10).max(100)).max(20).default([]),
    evidence_content_hashes: z
      .array(z.string().regex(/^[a-f0-9]{64}$/))
      .max(10)
      .default([]),
    contract_code_hash: z
      .string()
      .min(1).max(128)
      .nullable()
      .optional(),
    issued_at: z.number().int().positive(),
    expires_at: z.number().int().positive(),
    nonce: z.string().min(1).max(64),
    signature: z.string().regex(/^ed25519:[1-9A-HJ-NP-Za-km-z]{86,88}$/),
  })
  .refine((data) => data.expires_at > data.issued_at, {
    message: 'expires_at must be strictly greater than issued_at',
    path: ['expires_at'],
  });
export type SubmitReportRequest = z.infer<typeof SubmitReportRequestSchema>;

export const ReviewReportRequestSchema = z.object({
  decision: z.enum(['active_block', 'dismissed', 'corroborated', 'rejected']),
  scope: z.enum(['account', 'code_hash', 'both']).default('account'),
  reason: z.string().min(5).max(1000),
  block_expires_at: z.number().int().positive().optional(),
});
export type ReviewReportRequest = z.infer<typeof ReviewReportRequestSchema>;

export const ReviewRecordSchema = z.object({
  review_id: z.guid(),
  report_id: z.guid(),
  reviewer_id: z.string().min(2).max(64),
  status: ReportStatusSchema,
  decision: z.enum(['active_block', 'dismissed', 'corroborated', 'rejected']),
  scope: z.enum(['account', 'code_hash', 'both']),
  reason: z.string(),
  blocklist_entry_id: z.string().nullable(),
  blocklist_revision: z.number().int().nonnegative(),
  reviewed_at: z.number().int().positive(),
});
export type ReviewRecord = z.infer<typeof ReviewRecordSchema>;

export const ReportRecordSchema = z.object({
  report_id: z.guid(),
  network: z.enum(['testnet', 'mainnet', 'sandbox']),
  accused_account_id: z.string(),
  reporter_id: z.string(),
  reporter_public_key: z.string(),
  category: ReportCategorySchema,
  description: z.string(),
  transaction_references: z.array(z.string()),
  evidence_content_hashes: z.array(z.string()),
  contract_code_hash: z.string().nullable().optional(),
  status: ReportStatusSchema,
  issued_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
  nonce: z.string(),
  signature: z.string(),
  dependence_group_id: z.string().nullable().optional(),
  created_at: z.number().int().positive(),
});
export type ReportRecord = z.infer<typeof ReportRecordSchema>;

export const SubmitReportResponseSchema = z.object({
  report_id: z.guid(),
  status: z.literal('submitted'),
  issued_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
});
export type SubmitReportResponse = z.infer<typeof SubmitReportResponseSchema>;
export const ReportSubmitResponseSchema = SubmitReportResponseSchema;
export type ReportSubmitResponse = SubmitReportResponse;

export const DependenceGroupSummarySchema = z.object({
  groupId: z.string(),
  reporterCount: z.number().int().nonnegative(),
  effectiveWeight: z.number().nonnegative(),
  commonFunderId: z.string().optional(),
  faucetExempted: z.boolean(),
});
export type DependenceGroupSummary = z.infer<typeof DependenceGroupSummarySchema>;
export const DependenceGroupSchema = DependenceGroupSummarySchema;
export type DependenceGroup = DependenceGroupSummary;

export const ReportSummarySchema = z.object({
  report_id: z.guid(),
  reporter_id: z.string(),
  category: ReportCategorySchema,
  status: ReportStatusSchema,
  issued_at: z.number().int().positive(),
  effective_weight: z.number().nonnegative(),
  dependence_group_id: z.string().nullable().optional(),
});
export type ReportSummary = z.infer<typeof ReportSummarySchema>;
export const ReportItemSchema = ReportSummarySchema;
export type ReportItem = ReportSummary;

export const GetReportResponseSchema = z.object({
  report: ReportRecordSchema,
  review_history: z.array(ReviewRecordSchema),
  dependence_group: DependenceGroupSummarySchema.optional(),
});
export type GetReportResponse = z.infer<typeof GetReportResponseSchema>;
export const ReportDetailResponseSchema = GetReportResponseSchema;
export type ReportDetailResponse = GetReportResponse;

export const ReviewReportResponseSchema = z.object({
  review_id: z.guid(),
  status: z.string(),
  blocklist_revision: z.number().int().nonnegative(),
});
export type ReviewReportResponse = z.infer<typeof ReviewReportResponseSchema>;
export const ReportReviewResponseSchema = ReviewReportResponseSchema;
export type ReportReviewResponse = ReviewReportResponse;

export const ReceiverReportsResponseSchema = z.object({
  is_blocked: z.boolean(),
  total_reports: z.number().int().nonnegative(),
  effective_weight: z.number().nonnegative(),
  reports: z.array(ReportSummarySchema),
  dependence_groups: z.array(DependenceGroupSummarySchema),
});
export type ReceiverReportsResponse = z.infer<typeof ReceiverReportsResponseSchema>;

export const ReceiverReputationSchema = z.object({
  isBlocked: z.boolean(),
  blockReason: z.string().optional(),
  blocklistRevision: z.number().int().nonnegative(),
  rawReportCount: z.number().int().nonnegative(),
  effectiveReportWeight: z.number().nonnegative(),
  unresolvedReportsCount: z.number().int().nonnegative(),
  circularActivityDetected: z.boolean(),
  circularActivityScore: z.number().min(0).max(100),
  dependenceGroups: z.array(DependenceGroupSummarySchema),
  graphCoverage: z.object({
    accountsVisited: z.number().int().nonnegative(),
    edgesTraversed: z.number().int().nonnegative(),
    truncated: z.boolean(),
    windowDays: z.number().int().nonnegative(),
  }),
  reputationRiskPoints: z.number().int().min(0).max(100),
  reasonCodes: z.array(z.string()),
});
export type ReceiverReputation = z.infer<typeof ReceiverReputationSchema>;
