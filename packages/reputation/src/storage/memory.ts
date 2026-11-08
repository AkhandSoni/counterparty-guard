import type { ReportRecord } from '@counterparty-guard/shared';
import type { ReporterRecord } from './types.js';

export interface ReportIntakeStorage {
  getReporter(reporterId: string): Promise<ReporterRecord | null> | ReporterRecord | null;
  registerReporter(reporter: {
    reporter_id: string;
    public_key: string;
    network?: 'testnet' | 'mainnet' | 'sandbox';
    created_at?: number;
  }): Promise<void> | void;
  hasNonce(reporterId: string, nonce: string): Promise<boolean> | boolean;
  saveReport(report: ReportRecord): Promise<void> | void;
  getReport(reportId: string): Promise<ReportRecord | null> | ReportRecord | null;
}

export class InMemoryReportStorage implements ReportIntakeStorage {
  private reporters = new Map<string, ReporterRecord>();
  private reports = new Map<string, ReportRecord>();
  private nonces = new Set<string>(); // key: `${reporter_id}:${nonce}`

  getReporter(reporterId: string): ReporterRecord | null {
    return this.reporters.get(reporterId) ?? null;
  }

  registerReporter(reporter: {
    reporter_id: string;
    public_key: string;
    network?: 'testnet' | 'mainnet' | 'sandbox';
    created_at?: number;
  }): void {
    const existing = this.reporters.get(reporter.reporter_id);
    const now = reporter.created_at ?? Date.now();
    if (!existing) {
      this.reporters.set(reporter.reporter_id, {
        reporter_id: reporter.reporter_id,
        public_key: reporter.public_key,
        network: reporter.network ?? 'testnet',
        reputation_score: 1.0,
        total_reports: 0,
        created_at: now,
        updated_at: now,
      });
    } else {
      existing.public_key = reporter.public_key;
      existing.updated_at = now;
    }
  }

  hasNonce(reporterId: string, nonce: string): boolean {
    return this.nonces.has(`${reporterId}:${nonce}`);
  }

  saveReport(report: ReportRecord): void {
    const nonceKey = `${report.reporter_id}:${report.nonce}`;
    if (this.nonces.has(nonceKey)) {
      throw new Error('UNIQUE constraint failed: reports.reporter_id, reports.nonce');
    }
    this.nonces.add(nonceKey);
    this.reports.set(report.report_id, { ...report });
    const reporter = this.reporters.get(report.reporter_id);
    if (reporter) {
      reporter.total_reports += 1;
      reporter.updated_at = Date.now();
    }
  }

  getReport(reportId: string): ReportRecord | null {
    const r = this.reports.get(reportId);
    return r ? { ...r } : null;
  }

  getAllReports(): ReportRecord[] {
    return Array.from(this.reports.values());
  }

  clear(): void {
    this.reporters.clear();
    this.reports.clear();
    this.nonces.clear();
  }
}
