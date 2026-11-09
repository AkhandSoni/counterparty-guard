import crypto from 'node:crypto';
import type {
  ReportRecord,
  ReportStatus,
  ReviewRecord,
  ReviewReportRequest,
} from '@counterparty-guard/shared';

// ============================================================================
// Error Definitions
// ============================================================================

export class LifecycleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LifecycleError';
  }
}

export class ReviewerAuthorizationError extends LifecycleError {
  constructor(
    message = 'Unauthorized: Active block or review requires authenticated reviewer authority',
  ) {
    super(message);
    this.name = 'ReviewerAuthorizationError';
  }
}

export class InvalidStateTransitionError extends LifecycleError {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidStateTransitionError';
  }
}

export class ReportNotFoundError extends LifecycleError {
  constructor(reportId: string) {
    super(`Report with ID "${reportId}" not found`);
    this.name = 'ReportNotFoundError';
  }
}

export class ReportExpiredError extends LifecycleError {
  constructor(reportId: string) {
    super(`Report "${reportId}" has expired`);
    this.name = 'ReportExpiredError';
  }
}

// ============================================================================
// Core Interfaces & Models
// ============================================================================

export interface ReviewerContext {
  reviewer_id: string;
  role: 'reviewer' | 'admin';
  authenticated: boolean;
}

export interface TransactionReferenceCheck {
  reference: string;
  exists: boolean;
  network: string;
  block_height?: number;
  block_timestamp?: number;
  signer_id?: string;
  receiver_id?: string;
  matches_accused: boolean;
  details?: string;
}

export interface ReferenceVerificationResult {
  verified: boolean;
  total_references: number;
  matched_references: number;
  checks: TransactionReferenceCheck[];
  code_hash_matched?: boolean;
  failure_reason?: string;
  verified_at: number;
}

export interface CorroborationResult {
  corroborated: boolean;
  concurring_reports_count: number;
  independent_clusters_count: number;
  external_evidence_signals: string[];
  notes: string;
  corroborated_at: number;
}

export interface ActiveBlocklistEntry {
  entry_id: string;
  network: 'testnet' | 'mainnet' | 'sandbox';
  target_type: 'account' | 'code_hash' | 'both';
  account_id: string;
  code_hash: string | null;
  origin_report_id: string | null;
  origin_review_id: string;
  reviewer_id: string;
  reason: string;
  status: 'active' | 'revoked' | 'expired';
  created_at: number;
  expires_at: number | null;
  revoked_at: number | null;
  revocation_reason: string | null;
  revocation_reviewer_id: string | null;
}

export interface LifecycleRevisionRecord {
  revision: number;
  action: 'create' | 'update' | 'revoke' | 'expire';
  entry_id: string;
  network: 'testnet' | 'mainnet' | 'sandbox';
  target_type: 'account' | 'code_hash' | 'both';
  account_id: string;
  code_hash: string | null;
  reviewer_id: string;
  reason: string;
  report_id: string | null;
  created_at: number;
}

export interface IReferenceVerifier {
  verifyTransaction(
    network: string,
    txHash: string,
  ): Promise<{
    exists: boolean;
    signerId?: string;
    receiverId?: string;
    blockHeight?: number;
    timestamp?: number;
  }>;
  getAccountCodeHash?(network: string, accountId: string): Promise<string | null>;
}

export interface IReportLifecycleRepository {
  transaction?<T>(work: () => T): T;
  getActiveBlocksByReport(reportId: string): { entry_id: string }[];
  getReportById(reportId: string): ReportRecord | null;
  updateReportStatus(
    reportId: string,
    status: ReportStatus,
    dependenceGroupId?: string | null,
  ): void;

  createVerificationLog(record: {
    report_id: string;
    verified: boolean;
    matched_count: number;
    details: string;
    verified_at: number;
  }): void;

  createReview(record: ReviewRecord): void;
  getReviewsByReportId(reportId: string): ReviewRecord[];

  createBlocklistEntry(entry: ActiveBlocklistEntry): void;
  getActiveBlocklistEntry?(
    network: string,
    accountId: string,
    codeHash?: string | null,
  ): ActiveBlocklistEntry | null;
  revokeBlocklistEntry(
    entryId: string,
    params: { reviewer_id: string; reason: string; revoked_at: number },
  ): number;

  appendBlocklistRevision(
    revision: Omit<LifecycleRevisionRecord, 'revision'>,
  ): number;
  getLatestBlocklistRevision(): number;
  getBlocklistRevisions?(limit?: number): unknown[];

  findReportsByAccused(
    network: string,
    accusedAccountId: string,
  ): ReportRecord[];
}

// ============================================================================
// State Machine Rules & Transition Matrix
// ============================================================================

const VALID_TRANSITIONS: Record<ReportStatus, ReadonlySet<ReportStatus>> = {
  submitted: new Set([
    'references_verified',
    'corroborated',
    'reviewed',
    'rejected',
    'withdrawn',
    'expired',
  ]),
  references_verified: new Set(['corroborated', 'reviewed', 'rejected', 'withdrawn', 'expired']),
  corroborated: new Set(['reviewed', 'rejected', 'withdrawn', 'expired']),
  reviewed: new Set(['reviewed']), // re-reviews produce new review records & revision changes
  rejected: new Set(),
  withdrawn: new Set(),
  expired: new Set(),
};

export function canTransition(from: ReportStatus, to: ReportStatus): boolean {
  const allowed = VALID_TRANSITIONS[from];
  return allowed ? allowed.has(to) : false;
}

export function assertValidTransition(
  from: ReportStatus,
  to: ReportStatus,
  reportId: string,
): void {
  if (!canTransition(from, to)) {
    throw new InvalidStateTransitionError(
      `Illegal lifecycle transition from "${from}" to "${to}" for report ${reportId}`,
    );
  }
}

// ============================================================================
// Reviewer Authority Invariant Checks
// ============================================================================

export function assertReviewerAuthority(context: ReviewerContext): void {
  if (
    !context ||
    !context.authenticated ||
    (context.role !== 'reviewer' && context.role !== 'admin')
  ) {
    throw new ReviewerAuthorizationError(
      'Unauthorized: Active hard blocks require authenticated human reviewer authority. Agent tokens are not permitted.',
    );
  }
}

/**
 * Reviewer Authority Invariant:
 * Raw report count CANNOT trigger a hard block.
 * Only an active entry in `active_blocklist` created by an authenticated reviewer can trigger a block.
 */
export function evaluateBlockStatus(
  activeBlock:
    | ActiveBlocklistEntry
    | { is_active: number; reason: string; expires_at: number | null }
    | null,
  rawReportCount: number,
  now = Date.now(),
): { isBlocked: boolean; reason?: string; blocklistRevision?: number } {
  // Hard Invariant: regardless of rawReportCount (even if 100,000), if no active block exists, isBlocked is false.
  if (!activeBlock) {
    return { isBlocked: false };
  }

  const isActive =
    'status' in activeBlock ? activeBlock.status === 'active' : activeBlock.is_active === 1;

  if (!isActive) {
    return { isBlocked: false };
  }

  // Check TTL expiry
  if (activeBlock.expires_at !== null && activeBlock.expires_at <= now) {
    return { isBlocked: false };
  }

  return {
    isBlocked: true,
    reason: activeBlock.reason,
  };
}

// ============================================================================
// Lifecycle Engine Operations
// ============================================================================

export class ReportLifecycleEngine {
  constructor(private readonly repository: IReportLifecycleRepository) {}

  /**
   * Reference Verification Transition:
   * submitted -> references_verified (or rejected if references fail)
   */
  async verifyReferences(
    reportId: string,
    verifier: IReferenceVerifier,
    now = Date.now(),
  ): Promise<{ status: ReportStatus; result: ReferenceVerificationResult }> {
    const report = await this.repository.getReportById(reportId);
    if (!report) {
      throw new ReportNotFoundError(reportId);
    }

    if (now >= report.expires_at) {
      await this.repository.updateReportStatus(report.report_id, 'expired');
      throw new ReportExpiredError(reportId);
    }

    assertValidTransition(report.status, 'references_verified', reportId);

    const checks: TransactionReferenceCheck[] = [];
    let allMatched = true;

    for (const ref of report.transaction_references) {
      const tx = await verifier.verifyTransaction(report.network, ref);
      if (!tx.exists) {
        checks.push({
          reference: ref,
          exists: false,
          network: report.network,
          matches_accused: false,
          details: 'Transaction not found on chain',
        });
        allMatched = false;
        continue;
      }

      const matchesAccused =
        tx.receiverId === report.accused_account_id || tx.signerId === report.accused_account_id;

      checks.push({
        reference: ref,
        exists: true,
        network: report.network,
        block_height: tx.blockHeight,
        block_timestamp: tx.timestamp,
        signer_id: tx.signerId,
        receiver_id: tx.receiverId,
        matches_accused: matchesAccused,
        details: matchesAccused
          ? undefined
          : `Tx does not involve accused account ${report.accused_account_id}`,
      });

      if (!matchesAccused) {
        allMatched = false;
      }
    }

    let codeHashMatched: boolean | undefined;
    if (report.contract_code_hash && verifier.getAccountCodeHash) {
      const currentCodeHash = await verifier.getAccountCodeHash(
        report.network,
        report.accused_account_id,
      );
      codeHashMatched = currentCodeHash === report.contract_code_hash;
      if (codeHashMatched === false) {
        allMatched = false;
      }
    }

    const matchedCount = checks.filter((c) => c.matches_accused).length;
    // If no transaction references provided, verified holds true if evidence content hashes exist
    const isVerified = report.transaction_references.length === 0 || allMatched;

    const result: ReferenceVerificationResult = {
      verified: isVerified,
      total_references: report.transaction_references.length,
      matched_references: matchedCount,
      checks,
      code_hash_matched: codeHashMatched,
      failure_reason: isVerified
        ? undefined
        : 'One or more transaction references or contract code hash failed verification',
      verified_at: now,
    };

    await this.repository.createVerificationLog({
      report_id: report.report_id,
      verified: isVerified,
      matched_count: matchedCount,
      details: JSON.stringify(result),
      verified_at: now,
    });

    const nextStatus: ReportStatus = isVerified ? 'references_verified' : 'rejected';
    await this.repository.updateReportStatus(report.report_id, nextStatus);

    return { status: nextStatus, result };
  }

  /**
   * Corroboration Transition:
   * references_verified -> corroborated
   * Enforces Sybil group resistance: reports within the same dependence group do not corroborate.
   */
  async corroborate(
    reportId: string,
    options: {
      candidateReports?: ReportRecord[];
      externalIntelSignals?: string[];
      now?: number;
    } = {},
  ): Promise<{ status: ReportStatus; result: CorroborationResult }> {
    const now = options.now ?? Date.now();
    const report = await this.repository.getReportById(reportId);
    if (!report) {
      throw new ReportNotFoundError(reportId);
    }

    if (now >= report.expires_at) {
      await this.repository.updateReportStatus(report.report_id, 'expired');
      throw new ReportExpiredError(reportId);
    }

    assertValidTransition(report.status, 'corroborated', reportId);

    const candidates =
      options.candidateReports ??
      (await this.repository.findReportsByAccused(report.network, report.accused_account_id));

    const independentClusters = new Set<string>();
    const myCluster = report.dependence_group_id || `singleton_${report.reporter_id}`;

    for (const other of candidates) {
      if (other.report_id === report.report_id) continue;
      if (['references_verified', 'corroborated', 'reviewed'].includes(other.status)) {
        const otherCluster = other.dependence_group_id || `singleton_${other.reporter_id}`;
        // Sybil resistance: must not belong to the same cluster
        if (otherCluster !== myCluster) {
          independentClusters.add(otherCluster);
        }
      }
    }

    const externalSignals = options.externalIntelSignals ?? [];
    const isCorroborated = independentClusters.size >= 1 || externalSignals.length > 0;

    const result: CorroborationResult = {
      corroborated: isCorroborated,
      concurring_reports_count: candidates.filter((c) => c.report_id !== report.report_id).length,
      independent_clusters_count: independentClusters.size,
      external_evidence_signals: externalSignals,
      notes: isCorroborated
        ? `Corroborated by ${independentClusters.size} independent cluster(s) and ${externalSignals.length} external signal(s)`
        : 'Insufficient independent concurrence',
      corroborated_at: now,
    };

    if (isCorroborated) {
      await this.repository.updateReportStatus(report.report_id, 'corroborated');
      return { status: 'corroborated', result };
    }

    return { status: report.status, result };
  }

  /**
   * Review Transition:
   * references_verified | corroborated | submitted -> reviewed (or rejected)
   * Enforces Reviewer Authority Invariant and updates append-only blocklist revision.
   */
  async review(reportId: string, request: ReviewReportRequest, reviewer: ReviewerContext, now = Date.now()): Promise<{ review: ReviewRecord; blocklistRevision: number; newStatus: ReportStatus }> {
    const work = () => this.reviewNow(reportId, request, reviewer, now);
    return this.repository.transaction ? this.repository.transaction(work) : work();
  }
  private reviewNow(
    reportId: string,
    request: ReviewReportRequest,
    reviewer: ReviewerContext,
    now = Date.now(),
  ): { review: ReviewRecord; blocklistRevision: number; newStatus: ReportStatus } {
    assertReviewerAuthority(reviewer);

    const report = this.repository.getReportById(reportId);
    if (!report) {
      throw new ReportNotFoundError(reportId);
    }

    if (now >= report.expires_at) {
      this.repository.updateReportStatus(report.report_id, 'expired');
      throw new ReportExpiredError(reportId);
    }

    if (['rejected', 'withdrawn', 'expired'].includes(report.status)) {
      throw new InvalidStateTransitionError(
        `Cannot review report in terminal status "${report.status}"`,
      );
    }

    let targetStatus: ReportStatus = 'reviewed';
    let blocklistEntryId: string | null = null;
    let currentRevision = this.repository.getLatestBlocklistRevision();

    if (request.decision === 'active_block') {
      if (request.scope !== 'account' && !report.contract_code_hash) throw new InvalidStateTransitionError('Code scope requires an exact code identity');
      if (request.block_expires_at !== undefined && request.block_expires_at <= now) throw new InvalidStateTransitionError('Block expiry must be in the future');
    }
    if (['active_block', 'dismissed', 'rejected'].includes(request.decision)) {
      for (const entry of this.repository.getActiveBlocksByReport(report.report_id)) {
        currentRevision = this.repository.revokeBlocklistEntry(entry.entry_id, { reviewer_id: reviewer.reviewer_id, reason: request.reason, revoked_at: now });
      }
    }
    if (request.decision === 'active_block') {
      const entryId = crypto.randomUUID();
      const codeHash = request.scope !== 'account' ? report.contract_code_hash || null : null;

      const blockEntry: ActiveBlocklistEntry = {
        entry_id: entryId,
        network: report.network,
        target_type: request.scope,
        account_id: report.accused_account_id,
        code_hash: codeHash,
        origin_report_id: report.report_id,
        origin_review_id: crypto.randomUUID(),
        reviewer_id: reviewer.reviewer_id,
        reason: request.reason,
        status: 'active',
        created_at: now,
        expires_at: request.block_expires_at ?? report.expires_at,
        revoked_at: null,
        revocation_reason: null,
        revocation_reviewer_id: null,
      };

      this.repository.createBlocklistEntry(blockEntry);

      currentRevision = this.repository.appendBlocklistRevision({
        action: 'create',
        entry_id: entryId,
        network: report.network,
        target_type: request.scope,
        account_id: report.accused_account_id,
        code_hash: codeHash,
        reviewer_id: reviewer.reviewer_id,
        reason: request.reason,
        report_id: report.report_id,
        created_at: now,
      });

      blocklistEntryId = entryId;
      targetStatus = 'reviewed';
    } else if (request.decision === 'dismissed') {
      targetStatus = 'reviewed';
    } else if (request.decision === 'rejected') {
      targetStatus = 'rejected';
    } else if (request.decision === 'corroborated') {
      targetStatus = 'corroborated';
    }

    const reviewRecord: ReviewRecord = {
      review_id: crypto.randomUUID(),
      report_id: report.report_id,
      reviewer_id: reviewer.reviewer_id,
      status: targetStatus,
      decision: request.decision,
      scope: request.scope,
      reason: request.reason,
      blocklist_entry_id: blocklistEntryId,
      blocklist_revision: currentRevision,
      reviewed_at: now,
    };

    this.repository.createReview(reviewRecord);
    this.repository.updateReportStatus(report.report_id, targetStatus);

    return {
      review: reviewRecord,
      blocklistRevision: currentRevision,
      newStatus: targetStatus,
    };
  }

  /**
   * Revoke Active Block:
   * Authenticated reviewer unblocks an account. Appends new blocklist revision.
   */
  async revokeBlock(
    entryId: string,
    reason: string,
    reviewer: ReviewerContext,
    options: {
      network?: 'testnet' | 'mainnet' | 'sandbox';
      accountId?: string;
      now?: number;
    } = {},
  ): Promise<{ revision: number }> {
    assertReviewerAuthority(reviewer);

    if (!reason || reason.trim().length < 5) {
      throw new LifecycleError('Revocation requires a reason with at least 5 characters');
    }

    const now = options.now ?? Date.now();

    const revision = await this.repository.revokeBlocklistEntry(entryId, {
      reviewer_id: reviewer.reviewer_id,
      reason,
      revoked_at: now,
    });

    return { revision };
  }
}

// In-Memory Lifecycle Repository for isolated tests
export class MemoryReportLifecycleRepository implements IReportLifecycleRepository {
  public reports = new Map<string, ReportRecord>();
  public verificationLogs: Array<{
    report_id: string;
    verified: boolean;
    matched_count: number;
    details: string;
    verified_at: number;
  }> = [];
  public reviews = new Map<string, ReviewRecord[]>();
  public blocklist = new Map<string, ActiveBlocklistEntry>();
  public revisions: LifecycleRevisionRecord[] = [];

  getActiveBlocksByReport(reportId: string): { entry_id: string }[] {
    return [...this.blocklist.values()].filter(entry => entry.origin_report_id === reportId && entry.status === 'active');
  }
  getReportById(reportId: string): ReportRecord | null {
    return this.reports.get(reportId) ?? null;
  }

  updateReportStatus(
    reportId: string,
    status: ReportStatus,
    dependenceGroupId?: string | null,
  ): void {
    const report = this.reports.get(reportId);
    if (report) {
      report.status = status;
      if (dependenceGroupId !== undefined) {
        report.dependence_group_id = dependenceGroupId;
      }
    }
  }

  createVerificationLog(record: {
    report_id: string;
    verified: boolean;
    matched_count: number;
    details: string;
    verified_at: number;
  }): void {
    this.verificationLogs.push(record);
  }

  createReview(record: ReviewRecord): void {
    const list = this.reviews.get(record.report_id) ?? [];
    list.push(record);
    this.reviews.set(record.report_id, list);
  }

  getReviewsByReportId(reportId: string): ReviewRecord[] {
    return this.reviews.get(reportId) ?? [];
  }

  createBlocklistEntry(entry: ActiveBlocklistEntry): void {
    this.blocklist.set(entry.entry_id, { ...entry });
  }

  getActiveBlocklistEntry(
    network: string,
    accountId: string,
    codeHash?: string | null,
  ): ActiveBlocklistEntry | null {
    for (const entry of this.blocklist.values()) {
      if (entry.status === 'active' && entry.network === network) {
        if (entry.target_type === 'account' && entry.account_id === accountId) {
          return entry;
        }
        if (entry.target_type === 'code_hash' && entry.account_id === accountId && codeHash && entry.code_hash === codeHash) {
          return entry;
        }
        if (
          entry.target_type === 'both' &&
          entry.account_id === accountId &&
          (!entry.code_hash || entry.code_hash === codeHash)
        ) {
          return entry;
        }
      }
    }
    return null;
  }

  revokeBlocklistEntry(
    entryId: string,
    params: { reviewer_id: string; reason: string; revoked_at: number },
  ): number {
    const entry = this.blocklist.get(entryId);
    if (!entry) {
      throw new Error(`Active block entry not found: ${entryId}`);
    }
    entry.status = 'revoked';
    entry.revoked_at = params.revoked_at;
    entry.revocation_reason = params.reason;
    entry.revocation_reviewer_id = params.reviewer_id;
    return this.appendBlocklistRevision({
      action: 'revoke',
      entry_id: entryId,
      network: entry.network,
      target_type: entry.target_type,
      account_id: entry.account_id,
      code_hash: entry.code_hash,
      reviewer_id: params.reviewer_id,
      reason: params.reason,
      report_id: entry.origin_report_id,
      created_at: params.revoked_at,
    });
  }

  appendBlocklistRevision(revision: Omit<LifecycleRevisionRecord, 'revision'>): number {
    const nextRev = this.revisions.length + 1;
    this.revisions.push({ ...revision, revision: nextRev });
    return nextRev;
  }

  getLatestBlocklistRevision(): number {
    return this.revisions.length;
  }

  getBlocklistRevisions(limit = 100): LifecycleRevisionRecord[] {
    return this.revisions.slice(-limit);
  }

  findReportsByAccused(network: string, accusedAccountId: string): ReportRecord[] {
    const result: ReportRecord[] = [];
    for (const r of this.reports.values()) {
      if (r.network === network && r.accused_account_id === accusedAccountId) {
        result.push(r);
      }
    }
    return result;
  }
}
