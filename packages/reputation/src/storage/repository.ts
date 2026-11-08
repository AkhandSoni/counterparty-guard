import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type {
  ReportCategory,
  ReportRecord,
  ReportStatus,
  ReviewRecord,
} from '@counterparty-guard/shared';
import type {
  ActiveBlockRecord,
  BlocklistRevisionRecord,
  CreateActiveBlockInput,
  DependenceGroupRecord,
  EvidenceReferenceRecord,
  FaucetExemptionRecord,
  GroupMemberRecord,
  ReporterRecord,
  VerificationLogRecord,
} from './types.js';

export class ReportRepository {
  constructor(private readonly db: DatabaseSync) {}

  // ===================== REPORTERS =====================

  upsertReporter(params: {
    reporter_id: string;
    public_key: string;
    network: 'testnet' | 'mainnet' | 'sandbox';
  }): ReporterRecord {
    const now = Date.now();
    const existing = this.getReporter(params.reporter_id);
    if (!existing) {
      const stmt = this.db.prepare(`
        INSERT INTO reporters (reporter_id, public_key, network, reputation_score, total_reports, created_at, updated_at)
        VALUES (?, ?, ?, 1.0, 0, ?, ?)
      `);
      stmt.run(params.reporter_id, params.public_key, params.network, now, now);
    } else if (existing.public_key !== params.public_key) {
      const stmt = this.db.prepare(`
        UPDATE reporters SET public_key = ?, updated_at = ? WHERE reporter_id = ?
      `);
      stmt.run(params.public_key, now, params.reporter_id);
    }
    const reporter = this.getReporter(params.reporter_id);
    if (!reporter) {
      throw new Error(`Failed to retrieve upserted reporter: ${params.reporter_id}`);
    }
    return reporter;
  }

  registerReporter(reporter: {
    reporter_id: string;
    public_key: string;
    network?: 'testnet' | 'mainnet' | 'sandbox';
    created_at?: number;
  }): void {
    const now = reporter.created_at ?? Date.now();
    const network = reporter.network ?? 'testnet';
    const stmt = this.db.prepare(`
      INSERT INTO reporters (reporter_id, public_key, network, reputation_score, total_reports, created_at, updated_at)
      VALUES (?, ?, ?, 1.0, 0, ?, ?)
      ON CONFLICT(reporter_id) DO UPDATE SET
        public_key = excluded.public_key,
        updated_at = excluded.updated_at
    `);
    stmt.run(reporter.reporter_id, reporter.public_key, network, now, now);
  }

  getReporter(reporter_id: string): ReporterRecord | null {
    const stmt = this.db.prepare('SELECT * FROM reporters WHERE reporter_id = ?');
    return (stmt.get(reporter_id) as unknown as ReporterRecord) ?? null;
  }

  // ===================== REPORTS =====================

  hasNonce(reporter_id: string, nonce: string): boolean {
    const stmt = this.db.prepare('SELECT 1 FROM reports WHERE reporter_id = ? AND nonce = ?');
    return !!stmt.get(reporter_id, nonce);
  }

  hasReporterNonce(reporter_id: string, nonce: string): boolean {
    return this.hasNonce(reporter_id, nonce);
  }

  saveReport(report: ReportRecord): void {
    this.insertReport(report);
  }

  insertReport(report: ReportRecord): void {
    const stmt = this.db.prepare(`
      INSERT INTO reports (
        report_id, network, accused_account_id, reporter_id, reporter_public_key,
        category, description, transaction_references, evidence_content_hashes,
        contract_code_hash, status, issued_at, expires_at, nonce, signature,
        dependence_group_id, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      report.report_id,
      report.network,
      report.accused_account_id,
      report.reporter_id,
      report.reporter_public_key,
      report.category,
      report.description,
      JSON.stringify(report.transaction_references || []),
      JSON.stringify(report.evidence_content_hashes || []),
      report.contract_code_hash ?? null,
      report.status,
      report.issued_at,
      report.expires_at,
      report.nonce,
      report.signature,
      report.dependence_group_id ?? null,
      report.created_at,
      report.created_at,
    );

    // Increment reporter total_reports
    this.db
      .prepare(
        'UPDATE reporters SET total_reports = total_reports + 1, updated_at = ? WHERE reporter_id = ?',
      )
      .run(Date.now(), report.reporter_id);
  }

  getReport(report_id: string): ReportRecord | null {
    const stmt = this.db.prepare('SELECT * FROM reports WHERE report_id = ?');
    const row = stmt.get(report_id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.mapReportRow(row);
  }

  getReportById(report_id: string): ReportRecord | null {
    return this.getReport(report_id);
  }

  getReportsByAccused(network: string, accused_account_id: string): ReportRecord[] {
    const stmt = this.db.prepare(
      'SELECT * FROM reports WHERE network = ? AND accused_account_id = ? ORDER BY created_at DESC',
    );
    const rows = stmt.all(network, accused_account_id) as unknown as Record<string, unknown>[];
    return rows.map((r) => this.mapReportRow(r));
  }

  findReportsByAccused(network: string, accused_account_id: string): ReportRecord[] {
    return this.getReportsByAccused(network, accused_account_id);
  }

  updateReportStatus(
    report_id: string,
    status: ReportStatus,
    dependence_group_id?: string | null,
  ): void {
    const now = Date.now();
    if (dependence_group_id !== undefined) {
      this.db
        .prepare(
          'UPDATE reports SET status = ?, dependence_group_id = ?, updated_at = ? WHERE report_id = ?',
        )
        .run(status, dependence_group_id, now, report_id);
    } else {
      this.db
        .prepare('UPDATE reports SET status = ?, updated_at = ? WHERE report_id = ?')
        .run(status, now, report_id);
    }
  }

  private mapReportRow(row: Record<string, unknown>): ReportRecord {
    return {
      report_id: String(row.report_id),
      network: row.network as 'testnet' | 'mainnet' | 'sandbox',
      accused_account_id: String(row.accused_account_id),
      reporter_id: String(row.reporter_id),
      reporter_public_key: String(row.reporter_public_key),
      category: row.category as ReportCategory,
      description: String(row.description),
      transaction_references: JSON.parse(String(row.transaction_references || '[]')),
      evidence_content_hashes: JSON.parse(String(row.evidence_content_hashes || '[]')),
      contract_code_hash: row.contract_code_hash ? String(row.contract_code_hash) : null,
      status: row.status as ReportStatus,
      issued_at: Number(row.issued_at),
      expires_at: Number(row.expires_at),
      nonce: String(row.nonce),
      signature: String(row.signature),
      dependence_group_id: row.dependence_group_id ? String(row.dependence_group_id) : null,
      created_at: Number(row.created_at),
    };
  }

  // ===================== EVIDENCE & REVIEWS =====================

  insertEvidenceReference(params: {
    report_id: string;
    reference_type: 'transaction' | 'receipt' | 'content_hash' | 'account';
    reference_value: string;
  }): string {
    const evidence_id = randomUUID();
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO evidence_references (evidence_id, report_id, reference_type, reference_value, verified, created_at)
      VALUES (?, ?, ?, ?, 0, ?)
    `);
    stmt.run(
      evidence_id,
      params.report_id,
      params.reference_type,
      params.reference_value,
      Date.now(),
    );
    return evidence_id;
  }

  getEvidenceReferences(report_id: string): EvidenceReferenceRecord[] {
    const stmt = this.db.prepare('SELECT * FROM evidence_references WHERE report_id = ?');
    return stmt.all(report_id) as unknown as EvidenceReferenceRecord[];
  }

  insertVerificationLog(params: {
    report_id: string;
    verifier_type: 'chain_rpc' | 'content_verifier' | 'automated_heuristics' | 'reviewer';
    check_name: string;
    passed: boolean;
    details?: string;
  }): void {
    const stmt = this.db.prepare(`
      INSERT INTO verification_logs (log_id, report_id, verifier_type, check_name, passed, details, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      randomUUID(),
      params.report_id,
      params.verifier_type,
      params.check_name,
      params.passed ? 1 : 0,
      params.details ?? null,
      Date.now(),
    );
  }

  createVerificationLog(record: {
    report_id: string;
    verified: boolean;
    matched_count: number;
    details: string;
    verified_at: number;
  }): void {
    this.insertVerificationLog({
      report_id: record.report_id,
      verifier_type: 'reviewer',
      check_name: 'reference_verification',
      passed: record.verified,
      details: record.details,
    });
  }

  insertReview(review: ReviewRecord): void {
    const stmt = this.db.prepare(`
      INSERT INTO report_reviews (
        review_id, report_id, reviewer_id, status, decision, scope, reason,
        blocklist_entry_id, blocklist_revision, reviewed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      review.review_id,
      review.report_id,
      review.reviewer_id,
      review.status,
      review.decision,
      review.scope,
      review.reason,
      review.blocklist_entry_id ?? null,
      review.blocklist_revision,
      review.reviewed_at,
    );
  }

  createReview(record: ReviewRecord): void {
    this.insertReview(record);
  }

  getReviewsByReport(report_id: string): ReviewRecord[] {
    const stmt = this.db.prepare(
      'SELECT * FROM report_reviews WHERE report_id = ? ORDER BY reviewed_at ASC',
    );
    const rows = stmt.all(report_id) as unknown as Record<string, unknown>[];
    return rows.map((r) => ({
      review_id: String(r.review_id),
      report_id: String(r.report_id),
      reviewer_id: String(r.reviewer_id),
      status: r.status as ReportStatus,
      decision: r.decision as 'active_block' | 'dismissed' | 'corroborated' | 'rejected',
      scope: r.scope as 'account' | 'code_hash' | 'both',
      reason: String(r.reason),
      blocklist_entry_id: r.blocklist_entry_id ? String(r.blocklist_entry_id) : null,
      blocklist_revision: Number(r.blocklist_revision),
      reviewed_at: Number(r.reviewed_at),
    }));
  }

  getReviewsByReportId(report_id: string): ReviewRecord[] {
    return this.getReviewsByReport(report_id);
  }

  // ===================== BLOCKLIST & REVISIONS =====================

  getActiveBlock(
    network: 'testnet' | 'mainnet' | 'sandbox',
    accused_account_id: string,
    contract_code_hash?: string | null,
  ): ActiveBlockRecord | null {
    const now = Date.now();
    const query = `
      SELECT * FROM active_blocklist
      WHERE network = ? AND is_active = 1
        AND (expires_at IS NULL OR expires_at > ?)
        AND (
          (accused_account_id = ? AND scope IN ('account', 'both'))
          OR
          (contract_code_hash IS NOT NULL AND contract_code_hash = ? AND scope IN ('code_hash', 'both'))
        )
      ORDER BY created_at DESC
      LIMIT 1;
    `;
    const params: (string | number | null)[] = [
      network,
      now,
      accused_account_id,
      contract_code_hash ?? null,
    ];

    const row = this.db.prepare(query).get(...params) as unknown as ActiveBlockRecord | undefined;
    return row ?? null;
  }

  createActiveBlock(input: CreateActiveBlockInput): {
    entry_id: string;
    blocklist_revision: number;
  } {
    const entry_id = randomUUID();
    const now = Date.now();

    this.db.exec('BEGIN TRANSACTION;');
    try {
      // 1. Insert into active_blocklist
      this.db
        .prepare(`
          INSERT INTO active_blocklist (
            entry_id, network, accused_account_id, contract_code_hash, scope,
            reason, reviewer_id, report_id, is_active, created_at, expires_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        `)
        .run(
          entry_id,
          input.network,
          input.accused_account_id,
          input.contract_code_hash ?? null,
          input.scope,
          input.reason,
          input.reviewer_id,
          input.report_id ?? null,
          now,
          input.expires_at ?? null,
        );

      // 2. Append to blocklist_revisions ledger
      const res = this.db
        .prepare(`
          INSERT INTO blocklist_revisions (
            entry_id, action, network, accused_account_id, contract_code_hash,
            scope, reviewer_id, reason, created_at
          ) VALUES (?, 'added', ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          entry_id,
          input.network,
          input.accused_account_id,
          input.contract_code_hash ?? null,
          input.scope,
          input.reviewer_id,
          input.reason,
          now,
        );

      const blocklist_revision = Number(res.lastInsertRowid);
      this.db.exec('COMMIT;');
      return { entry_id, blocklist_revision };
    } catch (err) {
      this.db.exec('ROLLBACK;');
      throw err;
    }
  }

  createBlocklistEntry(entry: {
    entry_id: string;
    network: 'testnet' | 'mainnet' | 'sandbox';
    target_type: 'account' | 'code_hash' | 'both';
    account_id: string;
    code_hash: string | null;
    origin_report_id: string | null;
    reviewer_id: string;
    reason: string;
    status: 'active' | 'revoked' | 'expired';
    created_at: number;
    expires_at: number | null;
  }): void {
    const is_active = entry.status === 'active' ? 1 : 0;
    this.db
      .prepare(`
        INSERT INTO active_blocklist (
          entry_id, network, accused_account_id, contract_code_hash, scope,
          reason, reviewer_id, report_id, is_active, created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        entry.entry_id,
        entry.network,
        entry.account_id,
        entry.code_hash,
        entry.target_type,
        entry.reason,
        entry.reviewer_id,
        entry.origin_report_id,
        is_active,
        entry.created_at,
        entry.expires_at,
      );
  }

  revokeActiveBlock(
    entry_id: string,
    params: { reviewer_id: string; reason: string; revoked_at?: number },
  ): number {
    const revoked_at = params.revoked_at ?? Date.now();
    this.db.exec('BEGIN TRANSACTION;');
    try {
      const entry = this.db
        .prepare('SELECT * FROM active_blocklist WHERE entry_id = ?')
        .get(entry_id) as Record<string, unknown> | undefined;
      if (!entry) {
        throw new Error(`Active block entry not found: ${entry_id}`);
      }

      this.db
        .prepare(`
          UPDATE active_blocklist
          SET is_active = 0, revoked_at = ?, revoked_by = ?, revocation_reason = ?
          WHERE entry_id = ?
        `)
        .run(revoked_at, params.reviewer_id, params.reason, entry_id);

      const res = this.db
        .prepare(`
          INSERT INTO blocklist_revisions (
            entry_id, action, network, accused_account_id, contract_code_hash,
            scope, reviewer_id, reason, created_at
          ) VALUES (?, 'revoked', ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          entry_id,
          String(entry.network),
          String(entry.accused_account_id),
          entry.contract_code_hash ? String(entry.contract_code_hash) : null,
          String(entry.scope),
          params.reviewer_id,
          params.reason,
          revoked_at,
        );

      const revision = Number(res.lastInsertRowid);
      this.db.exec('COMMIT;');
      return revision;
    } catch (err) {
      this.db.exec('ROLLBACK;');
      throw err;
    }
  }

  revokeBlocklistEntry(
    entry_id: string,
    params: { reviewer_id: string; reason: string; revoked_at: number },
  ): number {
    return this.revokeActiveBlock(entry_id, params);
  }

  appendBlocklistRevision(revision: {
    action: string;
    entry_id: string;
    network: 'testnet' | 'mainnet' | 'sandbox';
    target_type: 'account' | 'code_hash' | 'both';
    account_id: string;
    code_hash: string | null;
    reviewer_id: string;
    reason: string;
    report_id: string | null;
    created_at: number;
  }): number {
    const action =
      revision.action === 'revoke'
        ? 'revoked'
        : revision.action === 'create'
          ? 'added'
          : revision.action;
    const res = this.db
      .prepare(`
        INSERT INTO blocklist_revisions (
          entry_id, action, network, accused_account_id, contract_code_hash,
          scope, reviewer_id, reason, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        revision.entry_id,
        action,
        revision.network,
        revision.account_id,
        revision.code_hash,
        revision.target_type,
        revision.reviewer_id,
        revision.reason,
        revision.created_at,
      );
    return Number(res.lastInsertRowid);
  }

  getLatestBlocklistRevision(): number {
    const row = this.db
      .prepare('SELECT MAX(revision_number) as max_rev FROM blocklist_revisions')
      .get() as { max_rev?: number } | undefined;
    return row?.max_rev ? Number(row.max_rev) : 0;
  }

  getBlocklistRevisions(limit = 100): BlocklistRevisionRecord[] {
    const stmt = this.db.prepare(
      'SELECT * FROM blocklist_revisions ORDER BY revision_number DESC LIMIT ?',
    );
    return stmt.all(limit) as unknown as BlocklistRevisionRecord[];
  }

  // ===================== DEPENDENCE GROUPS & FAUCETS =====================

  upsertDependenceGroup(group: DependenceGroupRecord): void {
    const stmt = this.db.prepare(`
      INSERT INTO dependence_groups (
        group_id, network, common_funder_id, faucet_exempted, effective_weight,
        reporter_count, clustering_reason, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(group_id) DO UPDATE SET
        effective_weight = excluded.effective_weight,
        reporter_count = excluded.reporter_count,
        faucet_exempted = excluded.faucet_exempted,
        updated_at = excluded.updated_at
    `);
    stmt.run(
      group.group_id,
      group.network,
      group.common_funder_id ?? null,
      group.faucet_exempted,
      group.effective_weight,
      group.reporter_count,
      group.clustering_reason,
      group.created_at,
      group.updated_at,
    );
  }

  getDependenceGroup(group_id: string): DependenceGroupRecord | null {
    const stmt = this.db.prepare('SELECT * FROM dependence_groups WHERE group_id = ?');
    return (stmt.get(group_id) as unknown as DependenceGroupRecord) ?? null;
  }

  addGroupMember(group_id: string, account_id: string, role = 'reporter', hops = 1): void {
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO group_members (membership_id, group_id, account_id, role, hops_from_funder, observed_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(randomUUID(), group_id, account_id, role, hops, Date.now());
  }

  getGroupMembers(group_id: string): GroupMemberRecord[] {
    const stmt = this.db.prepare('SELECT * FROM group_members WHERE group_id = ?');
    return stmt.all(group_id) as unknown as GroupMemberRecord[];
  }

  isFaucetExempted(network: 'testnet' | 'mainnet' | 'sandbox', account_id: string): boolean {
    const stmt = this.db.prepare(
      'SELECT 1 FROM faucet_exemptions WHERE network = ? AND faucet_account_id = ? AND is_active = 1',
    );
    return !!stmt.get(network, account_id);
  }

  getFaucetExemptions(network: 'testnet' | 'mainnet' | 'sandbox'): FaucetExemptionRecord[] {
    const stmt = this.db.prepare(
      'SELECT * FROM faucet_exemptions WHERE network = ? AND is_active = 1',
    );
    return stmt.all(network) as unknown as FaucetExemptionRecord[];
  }
}
