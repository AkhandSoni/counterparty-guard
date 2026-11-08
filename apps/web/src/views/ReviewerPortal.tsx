import type React from 'react';
import { useMemo, useState } from 'react';
import {
  AlertTriangleIcon,
  BanIcon,
  CheckCircleIcon,
  CheckIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  ShieldIcon,
} from '../components/Icons';
import type { Network, ReportCategory, ReportItem } from '../types';

export interface BlocklistRevisionItem {
  revisionNumber: number;
  entryId: string;
  action: 'added' | 'updated' | 'revoked' | 'expired';
  network: Network;
  accusedAccountId: string;
  contractCodeHash?: string | null;
  scope: 'account' | 'code_hash' | 'both';
  reviewerId: string;
  reason: string;
  createdAt: number;
}

export interface ReviewerPortalProps {
  initialReports?: ReportItem[];
  initialRevisions?: BlocklistRevisionItem[];
  initialSessionMode?: 'authenticated_reviewer' | 'unauthenticated_agent';
}

const DEFAULT_REPORTS: ReportItem[] = [
  {
    id: 'rep_001',
    accusedAccountId: 'known-drainer.testnet',
    reporterId: 'reporter1.testnet',
    category: 'drainer',
    description: 'Drained 10 NEAR via unauthorized transfer after spoofing vendor invoice.',
    status: 'corroborated',
    evidenceHashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    txReferences: ['9ZpQ7wKmT42vNx87YkL59a12b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2'],
    issuedAt: Date.now() - 3600000,
    dependenceGroupId: 'dep_group_alpha',
  },
  {
    id: 'rep_002',
    accusedAccountId: 'phishing-target.testnet',
    reporterId: 'reporter2.testnet',
    category: 'phishing',
    description: 'Impersonating NEAR official staking portal in bot telegram message.',
    status: 'submitted',
    evidenceHashes: ['a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e'],
    txReferences: [],
    issuedAt: Date.now() - 7200000,
  },
  {
    id: 'rep_003',
    accusedAccountId: 'exploitative-vault.testnet',
    reporterId: 'auditor.testnet',
    category: 'malicious_contract',
    description: 'Verified reentrancy vector in claim function causing token drain on testnet.',
    status: 'references_verified',
    evidenceHashes: ['7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d'],
    txReferences: ['4Kz8mQ7Yp1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8'],
    issuedAt: Date.now() - 14400000,
  },
];

const DEFAULT_REVISIONS: BlocklistRevisionItem[] = [
  {
    revisionNumber: 7,
    entryId: 'blk_007',
    action: 'added',
    network: 'testnet',
    accusedAccountId: 'drainer-v1.testnet',
    scope: 'account',
    reviewerId: 'moderator.testnet',
    reason: 'Verified drain receipt on-chain and confirmed malicious intent.',
    createdAt: Date.now() - 3600000,
  },
  {
    revisionNumber: 6,
    entryId: 'blk_006',
    action: 'added',
    network: 'testnet',
    accusedAccountId: 'codehash-exploit.testnet',
    contractCodeHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    scope: 'code_hash',
    reviewerId: 'security-lead.testnet',
    reason: 'Reentrancy vulnerability confirmed in bytecode decompilation analysis.',
    createdAt: Date.now() - 18000000,
  },
  {
    revisionNumber: 5,
    entryId: 'blk_005',
    action: 'revoked',
    network: 'testnet',
    accusedAccountId: 'false-alarm.testnet',
    scope: 'account',
    reviewerId: 'moderator.testnet',
    reason: 'Disproved phishing allegation after vendor confirmed invoice authenticity.',
    createdAt: Date.now() - 86400000,
  },
];

export const ReviewerPortal: React.FC<ReviewerPortalProps> = ({
  initialReports = DEFAULT_REPORTS,
  initialRevisions = DEFAULT_REVISIONS,
  initialSessionMode = 'authenticated_reviewer',
}) => {
  // Queue & Revision State
  const [reports, setReports] = useState<ReportItem[]>(initialReports);
  const [revisions, setRevisions] = useState<BlocklistRevisionItem[]>(initialRevisions);
  const [selectedReportId, setSelectedReportId] = useState<string>('rep_001');
  const [statusFilter, setStatusFilter] = useState<
    'all' | 'submitted' | 'references_verified' | 'corroborated'
  >('all');

  // Reviewer Authentication Session State
  const [sessionMode, setSessionMode] = useState<
    'authenticated_reviewer' | 'unauthenticated_agent'
  >(initialSessionMode);

  // Moderation Action Form State
  const [decision, setDecision] = useState<'active_block' | 'dismissed' | 'corroborated'>(
    'active_block',
  );
  const [scope, setScope] = useState<'account' | 'code_hash' | 'both'>('account');
  const [codeHashInput, setCodeHashInput] = useState<string>('');
  const [reason, setReason] = useState<string>(
    'Verified drain receipt on-chain and confirmed malicious intent.',
  );
  const [validationError, setValidationError] = useState<string | null>(null);
  const [actionSuccessNotice, setActionSuccessNotice] = useState<string | null>(null);

  // Filtered queue
  const filteredReports = useMemo(() => {
    if (statusFilter === 'all') return reports;
    return reports.filter((r) => r.status === statusFilter);
  }, [reports, statusFilter]);

  // Selected report lookup
  const selectedReport = useMemo(
    () => reports.find((r) => r.id === selectedReportId) || reports[0],
    [reports, selectedReportId],
  );

  const currentRevisionNumber = revisions.length > 0 ? revisions[0].revisionNumber : 7;

  const handleReviewSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);

    // Enforce Reviewer Auth Security Barrier
    if (sessionMode !== 'authenticated_reviewer') {
      setValidationError(
        '403 Forbidden: Reviewer authentication required. Automated agents cannot alter blocklists or commit review decisions.',
      );
      return;
    }

    // Enforce Mandatory Audit Reason Validation (min 5 chars)
    if (!reason || reason.trim().length < 5) {
      setValidationError(
        'Review reason is strictly mandatory (minimum 5 characters) for the append-only audit log.',
      );
      return;
    }

    if (!selectedReport) {
      setValidationError('No report selected in the queue.');
      return;
    }

    if (decision === 'active_block') {
      const nextRevision = currentRevisionNumber + 1;
      const newRevisionEntry: BlocklistRevisionItem = {
        revisionNumber: nextRevision,
        entryId: `blk_${Date.now()}`,
        action: 'added',
        network: 'testnet',
        accusedAccountId: selectedReport.accusedAccountId,
        contractCodeHash:
          scope === 'code_hash' || scope === 'both'
            ? codeHashInput || selectedReport.evidenceHashes[0] || null
            : null,
        scope,
        reviewerId: 'moderator.testnet',
        reason: reason.trim(),
        createdAt: Date.now(),
      };

      setRevisions([newRevisionEntry, ...revisions]);
      setReports((prev) =>
        prev.map((r) => (r.id === selectedReport.id ? { ...r, status: 'reviewed' } : r)),
      );

      setActionSuccessNotice(
        `Blocklist Revision #${nextRevision} Recorded: Hard block activated for ${selectedReport.accusedAccountId} (${scope}).`,
      );
    } else if (decision === 'dismissed') {
      setReports((prev) =>
        prev.map((r) => (r.id === selectedReport.id ? { ...r, status: 'dismissed' } : r)),
      );
      setActionSuccessNotice(
        `Report ${selectedReport.id} dismissed. Security Invariant Preserved: No blocklist modification made.`,
      );
    } else if (decision === 'corroborated') {
      setReports((prev) =>
        prev.map((r) => (r.id === selectedReport.id ? { ...r, status: 'corroborated' } : r)),
      );
      setActionSuccessNotice(
        `Report ${selectedReport.id} corroboration confirmed. Invariant Preserved: Corroboration alone does not block.`,
      );
    }
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case 'submitted':
        return 'bg-blue-950/80 border-blue-700 text-blue-300';
      case 'references_verified':
        return 'bg-cyan-950/80 border-cyan-700 text-cyan-300';
      case 'corroborated':
        return 'bg-amber-950/80 border-amber-700 text-amber-300';
      case 'reviewed':
        return 'bg-purple-950/80 border-purple-700 text-purple-300';
      case 'dismissed':
        return 'bg-slate-800 border-slate-600 text-slate-400';
      default:
        return 'bg-slate-800 border-slate-700 text-slate-300';
    }
  };

  const getActionBadgeClass = (action: string) => {
    switch (action) {
      case 'added':
        return 'bg-rose-950/80 border-rose-800 text-rose-300';
      case 'revoked':
        return 'bg-emerald-950/80 border-emerald-800 text-emerald-300';
      case 'updated':
        return 'bg-amber-950/80 border-amber-800 text-amber-300';
      default:
        return 'bg-slate-800 border-slate-700 text-slate-300';
    }
  };

  return (
    <div className="space-y-6">
      {/* Reviewer Auth Barrier & Header */}
      <div className="bg-purple-950/40 border border-purple-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-purple-900 border border-purple-700 text-purple-300 shrink-0">
            <ShieldAlertIcon size={22} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-white">Reviewer Moderation Portal</h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-900/60 border border-purple-700 text-purple-200">
                {`Blocklist Revision: #${currentRevisionNumber}`}
              </span>
            </div>
            <p className="text-xs text-purple-300">
              {sessionMode === 'authenticated_reviewer' ? (
                <>
                  Authenticated Session:{' '}
                  <span className="font-mono font-bold text-white">moderator.testnet</span>{' '}
                  (Security Officer / Reviewer Authority)
                </>
              ) : (
                <span className="text-rose-400 font-semibold">
                  Autonomous Agent Session: agent.testnet (Intake Only — No Review Authority)
                </span>
              )}
            </p>
          </div>
        </div>

        {/* Auth Session Switcher */}
        <div className="flex items-center gap-2 self-start md:self-auto">
          <span className="text-[11px] text-slate-400">Simulate Auth Session:</span>
          <button
            type="button"
            data-testid="toggle-auth-session-btn"
            onClick={() =>
              setSessionMode(
                sessionMode === 'authenticated_reviewer'
                  ? 'unauthenticated_agent'
                  : 'authenticated_reviewer',
              )
            }
            className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition ${
              sessionMode === 'authenticated_reviewer'
                ? 'bg-purple-900/80 hover:bg-purple-800 border-purple-600 text-purple-200'
                : 'bg-rose-950/80 hover:bg-rose-900 border-rose-700 text-rose-200'
            }`}
          >
            {sessionMode === 'authenticated_reviewer'
              ? '✓ Reviewer Authenticated'
              : '✕ Unauthenticated Agent (403)'}
          </button>
        </div>
      </div>

      {/* Security Invariant Callout */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-start gap-3">
        <ShieldCheckIcon size={20} className="text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs space-y-1">
          <span className="font-bold text-slate-200 block">
            Security Invariant: Raw Unreviewed Reports Cannot Block
          </span>
          <p className="text-slate-400">
            Unreviewed report intake swarms (regardless of volume, e.g. coordinated Sybil floods)
            can only contribute to soft reputation discounting and trigger a{' '}
            <span className="font-mono text-amber-400 font-semibold">WARN</span> outcome. Only an
            explicit, authenticated human reviewer action (active_block) creates an immutable entry
            in the active blocklist.
          </p>
        </div>
      </div>

      {/* Main Layout: Queue (Left) & Action / Inspector (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Moderation Queue */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <h3 className="font-semibold text-white text-sm">Pending Allegations Queue</h3>

            {/* Filter Tabs */}
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-[11px] font-mono">
              {(
                [
                  { id: 'all', label: 'All' },
                  { id: 'submitted', label: 'Submitted' },
                  { id: 'references_verified', label: 'Verified' },
                  { id: 'corroborated', label: 'Corroborated' },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setStatusFilter(tab.id)}
                  className={`px-2 py-0.5 rounded transition ${
                    statusFilter === tab.id
                      ? 'bg-purple-900/80 text-purple-200 font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            {filteredReports.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
                No reports matching filter &quot;{statusFilter}&quot;
              </div>
            ) : (
              filteredReports.map((rep) => {
                const isSelected = selectedReport?.id === rep.id;
                return (
                  <button
                    type="button"
                    key={rep.id}
                    onClick={() => {
                      setSelectedReportId(rep.id);
                      setActionSuccessNotice(null);
                      setValidationError(null);
                    }}
                    className={`w-full text-left p-3.5 rounded-lg border text-xs cursor-pointer transition ${
                      isSelected
                        ? 'bg-slate-950 border-purple-500 ring-1 ring-purple-500 shadow-md'
                        : 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-mono font-bold text-white break-all">
                        {rep.accusedAccountId}
                      </span>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-950 border border-purple-800 text-purple-300 uppercase">
                          {rep.category}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getStatusBadgeClass(
                            rep.status,
                          )}`}
                        >
                          {rep.status}
                        </span>
                      </div>
                    </div>
                    <p className="text-slate-400 line-clamp-2">{rep.description}</p>
                    <div className="flex items-center justify-between mt-2 pt-2 border-t border-slate-900 text-[10px] text-slate-500 font-mono">
                      <span>{`Reporter: ${rep.reporterId}`}</span>
                      {rep.dependenceGroupId && (
                        <span className="text-amber-400">{`Group: ${rep.dependenceGroupId}`}</span>
                      )}
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Action Panel & Selected Report Inspection */}
        <div className="lg:col-span-5 space-y-4">
          {/* Action Form */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h3 className="font-semibold text-white text-sm border-b border-slate-800 pb-2">
              Moderator Action & Audit Record
            </h3>

            {/* Validation or 403 Error Alert */}
            {validationError && (
              <div
                data-testid="reviewer-error-alert"
                className="p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-start gap-2"
              >
                <AlertTriangleIcon size={16} className="text-rose-400 shrink-0 mt-0.5" />
                <span>{validationError}</span>
              </div>
            )}

            {/* Success Confirmation Alert */}
            {actionSuccessNotice && (
              <div
                data-testid="reviewer-success-alert"
                className="p-3.5 rounded-lg bg-emerald-950/60 border border-emerald-800 text-emerald-300 text-xs space-y-2"
              >
                <div className="flex items-center gap-2">
                  <CheckCircleIcon size={16} className="text-emerald-400" />
                  <span className="font-bold">Moderation Action Committed</span>
                </div>
                <p className="text-[11px] text-emerald-400 leading-relaxed">
                  {actionSuccessNotice}
                </p>
              </div>
            )}

            <form onSubmit={handleReviewSubmit} className="space-y-3.5 text-xs">
              {/* Selected Target Display */}
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1">
                <span className="text-slate-400 block text-[11px]">Selected Accused Account:</span>
                <span className="font-mono text-cyan-400 font-semibold break-all">
                  {selectedReport ? selectedReport.accusedAccountId : 'None selected'}
                </span>
              </div>

              {/* Decision Selection */}
              <div>
                <label htmlFor="decision-select" className="block text-slate-400 mb-1 font-medium">
                  Moderator Decision Action
                </label>
                <select
                  id="decision-select"
                  data-testid="decision-select"
                  value={decision}
                  onChange={(e) =>
                    setDecision(e.target.value as 'active_block' | 'dismissed' | 'corroborated')
                  }
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-200 font-mono focus:border-purple-500 focus:outline-none"
                >
                  <option value="active_block">Activate Hard Block (active_block)</option>
                  <option value="corroborated">Confirm Corroboration (corroborated)</option>
                  <option value="dismissed">Dismiss Allegation (dismissed)</option>
                </select>
              </div>

              {/* Scope Selection */}
              <div>
                <label htmlFor="scope-select" className="block text-slate-400 mb-1 font-medium">
                  Block Enforcement Scope
                </label>
                <select
                  id="scope-select"
                  data-testid="scope-select"
                  value={scope}
                  onChange={(e) => setScope(e.target.value as 'account' | 'code_hash' | 'both')}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-200 font-mono focus:border-purple-500 focus:outline-none"
                >
                  <option value="account">Account Only</option>
                  <option value="code_hash">Contract Bytecode Hash Only</option>
                  <option value="both">Both Account & Bytecode</option>
                </select>
              </div>

              {/* Optional Code Hash Input for code_hash / both */}
              {(scope === 'code_hash' || scope === 'both') && (
                <div>
                  <label htmlFor="codehash-input" className="block text-slate-400 mb-1 font-medium">
                    Target Bytecode Hash (SHA256 Hex)
                  </label>
                  <input
                    id="codehash-input"
                    data-testid="codehash-input"
                    type="text"
                    value={codeHashInput}
                    onChange={(e) => setCodeHashInput(e.target.value)}
                    placeholder="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-cyan-300 font-mono text-xs focus:border-purple-500 focus:outline-none"
                  />
                </div>
              )}

              {/* Mandatory Audit Reason */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label htmlFor="reason-textarea" className="block text-slate-400 font-medium">
                    Mandatory Audit Reason (Strict)
                  </label>
                  <span className="text-[10px] text-slate-500 font-mono">
                    {reason.length} chars (min 5)
                  </span>
                </div>
                <textarea
                  id="reason-textarea"
                  data-testid="reason-textarea"
                  rows={3}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:border-purple-500 focus:outline-none text-xs"
                  placeholder="Provide explicit factual justification for the immutable audit trail..."
                />
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                data-testid="commit-review-btn"
                disabled={sessionMode !== 'authenticated_reviewer'}
                className={`w-full py-2.5 px-4 rounded-lg font-medium transition shadow-sm text-xs ${
                  sessionMode === 'authenticated_reviewer'
                    ? 'bg-purple-700 hover:bg-purple-600 text-white cursor-pointer'
                    : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-800'
                }`}
              >
                {sessionMode === 'authenticated_reviewer'
                  ? 'Commit Moderation Record (Increment Revision)'
                  : '403 Forbidden (Reviewer Auth Required)'}
              </button>
            </form>
          </div>

          {/* Selected Report Inspection Box */}
          {selectedReport && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-xs space-y-2">
              <span className="font-semibold text-slate-300 block text-xs border-b border-slate-800 pb-1.5">
                {`Evidence References (${selectedReport.id})`}
              </span>
              <div className="space-y-1 text-[11px] font-mono text-slate-400">
                <div>
                  <span className="text-slate-500">Tx References: </span>
                  {selectedReport.txReferences.length > 0 ? (
                    <span className="text-cyan-400">{selectedReport.txReferences.join(', ')}</span>
                  ) : (
                    <span className="text-slate-600">None attached</span>
                  )}
                </div>
                <div>
                  <span className="text-slate-500">Evidence Hashes: </span>
                  <span className="text-slate-300 break-all">
                    {selectedReport.evidenceHashes.join(', ')}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Immutable Blocklist Revision History Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h3 className="font-semibold text-white text-sm">
              Immutable Blocklist Revision History (Append-Only Log)
            </h3>
            <p className="text-xs text-slate-400">
              Every blocklist mutation is cryptographically signed and recorded with reviewer
              identity, scope, and timestamp.
            </p>
          </div>
          <span className="text-xs font-mono px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-cyan-400">
            {`Total Revisions: ${revisions.length}`}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                <th className="py-2.5 px-3">Revision</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Target Account / Code Hash</th>
                <th className="py-2.5 px-3">Scope</th>
                <th className="py-2.5 px-3">Reviewer ID</th>
                <th className="py-2.5 px-3">Mandatory Reason</th>
                <th className="py-2.5 px-3">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {revisions.map((rev) => (
                <tr key={rev.revisionNumber} className="hover:bg-slate-950/40 transition">
                  <td className="py-2.5 px-3 font-bold text-purple-300">{`#${rev.revisionNumber}`}</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] uppercase border font-semibold ${getActionBadgeClass(
                        rev.action,
                      )}`}
                    >
                      {rev.action.toUpperCase()}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-200 break-all max-w-[200px]">
                    <div>{rev.accusedAccountId}</div>
                    {rev.contractCodeHash && (
                      <div className="text-[10px] text-cyan-400 truncate">
                        {`code:${rev.contractCodeHash}`}
                      </div>
                    )}
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 uppercase text-[10px]">{rev.scope}</td>
                  <td className="py-2.5 px-3 text-slate-400">{rev.reviewerId}</td>
                  <td className="py-2.5 px-3 text-slate-300 max-w-[280px] break-words">
                    {rev.reason}
                  </td>
                  <td className="py-2.5 px-3 text-slate-500 text-[10px] whitespace-nowrap">
                    {new Date(rev.createdAt).toLocaleTimeString([], {
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default ReviewerPortal;
