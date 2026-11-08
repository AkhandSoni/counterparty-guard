import type { ScenarioId } from '@counterparty-guard/shared';
import type React from 'react';
import { useEffect, useState } from 'react';
import { DecisionBadge } from '../components/Badge';
import {
  ActivityIcon,
  AlertTriangleIcon,
  BanIcon,
  CheckCircleIcon,
  CheckIcon,
  CopyIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
} from '../components/Icons';
import { RiskMeter } from '../components/RiskMeter';
import {
  SCENARIO_RECEIVER_EVIDENCE,
  getReceiverEvidence,
  getScenarioEvidence,
} from '../data/mockReceiverEvidence';
import type {
  Network,
  ReceiverEvidenceData,
  ReportCategory,
  ReportItem,
  ReportStatus,
  TimelineEvent,
} from '../types';

export interface EvidenceTimelineProps {
  initialTargetAccountId?: string;
  initialScenarioId?: ScenarioId;
  network?: Network;
}

const CATEGORY_STYLES: Record<ReportCategory, string> = {
  drainer: 'bg-rose-950/80 border-rose-700 text-rose-300',
  phishing: 'bg-amber-950/80 border-amber-700 text-amber-300',
  malicious_contract: 'bg-red-950/80 border-red-700 text-red-300',
  impersonation: 'bg-orange-950/80 border-orange-700 text-orange-300',
  prompt_injection_source: 'bg-purple-950/80 border-purple-700 text-purple-300',
  wash_trading: 'bg-cyan-950/80 border-cyan-700 text-cyan-300',
  other: 'bg-slate-800 border-slate-700 text-slate-300',
};

const STATUS_STYLES: Record<ReportStatus, string> = {
  submitted: 'bg-blue-950/80 border-blue-700 text-blue-300',
  references_verified: 'bg-cyan-950/80 border-cyan-700 text-cyan-300',
  corroborated: 'bg-purple-950/80 border-purple-700 text-purple-300',
  reviewed: 'bg-rose-950/80 border-rose-700 text-rose-300',
  dismissed: 'bg-emerald-950/80 border-emerald-700 text-emerald-300',
  rejected: 'bg-slate-800 border-slate-600 text-slate-400',
  withdrawn: 'bg-zinc-900 border-zinc-700 text-zinc-400',
  expired: 'bg-zinc-900 border-zinc-700 text-zinc-400',
};

export const EvidenceTimeline: React.FC<EvidenceTimelineProps> = ({
  initialTargetAccountId,
  initialScenarioId = 'S4',
  network = 'testnet',
}) => {
  const [selectedScenarioId, setSelectedScenarioId] = useState<ScenarioId | 'CUSTOM'>(
    initialTargetAccountId ? 'CUSTOM' : initialScenarioId,
  );
  const [targetInput, setTargetInput] = useState<string>(
    initialTargetAccountId ||
      (initialScenarioId
        ? SCENARIO_RECEIVER_EVIDENCE[initialScenarioId]?.accountId
        : 'popular-service.testnet'),
  );
  const [activeAccount, setActiveAccount] = useState<string>(
    initialTargetAccountId ||
      (initialScenarioId
        ? SCENARIO_RECEIVER_EVIDENCE[initialScenarioId]?.accountId
        : 'popular-service.testnet'),
  );
  const [evidenceData, setEvidenceData] = useState<ReceiverEvidenceData>(() => {
    if (initialTargetAccountId) {
      return getReceiverEvidence(initialTargetAccountId, network);
    }
    if (initialScenarioId && SCENARIO_RECEIVER_EVIDENCE[initialScenarioId]) {
      return getScenarioEvidence(initialScenarioId);
    }
    return getReceiverEvidence('popular-service.testnet', network);
  });
  const [timelineFilter, setTimelineFilter] = useState<'all' | 'contract' | 'reports' | 'txs'>(
    'all',
  );
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Sync state if initialTargetAccountId changes
  useEffect(() => {
    if (initialTargetAccountId) {
      setActiveAccount(initialTargetAccountId);
      setTargetInput(initialTargetAccountId);
      setEvidenceData(getReceiverEvidence(initialTargetAccountId, network));
    }
  }, [initialTargetAccountId, network]);

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(label);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleSelectScenario = (scenId: ScenarioId) => {
    setSelectedScenarioId(scenId);
    const data = getScenarioEvidence(scenId);
    setActiveAccount(data.accountId);
    setTargetInput(data.accountId);
    setEvidenceData(data);
  };

  const handleInspectTarget = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = targetInput.trim().toLowerCase();
    if (!clean) return;

    // Check if clean matches known scenario
    const matchedScen = (Object.keys(SCENARIO_RECEIVER_EVIDENCE) as ScenarioId[]).find(
      (s) => SCENARIO_RECEIVER_EVIDENCE[s].accountId.toLowerCase() === clean,
    );

    if (matchedScen) {
      setSelectedScenarioId(matchedScen);
      setEvidenceData(getScenarioEvidence(matchedScen));
    } else {
      setSelectedScenarioId('CUSTOM');
      setEvidenceData(getReceiverEvidence(clean, network));
    }
    setActiveAccount(clean);
  };

  const filteredEvents = evidenceData.events.filter((evt) => {
    if (timelineFilter === 'all') return true;
    if (timelineFilter === 'contract') return evt.type === 'deployment' || !!evt.codeHash;
    if (timelineFilter === 'reports') return evt.type === 'report';
    if (timelineFilter === 'txs') return evt.type === 'interaction' || !!evt.txHash;
    return true;
  });

  const scenarioShortcuts: ScenarioId[] = ['S1', 'S3', 'S4', 'S5', 'S6', 'S7'];

  return (
    <div className="space-y-6">
      {/* Top Bar: Scenario Quick Selector & Search Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <ActivityIcon size={18} className="text-cyan-400" />
              Receiver Evidence Timeline & Graph Panel
            </h2>
            <p className="text-xs text-slate-400">
              Historical observations, report audit trails, and bounded graph explanations
            </p>
          </div>

          <form onSubmit={handleInspectTarget} className="flex items-center gap-2">
            <input
              type="text"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="target.testnet"
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 focus:outline-none w-48 sm:w-60"
            />
            <button
              type="submit"
              className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition"
            >
              Inspect Target
            </button>
          </form>
        </div>

        {/* Quick Scenario Buttons */}
        <div className="flex items-center gap-1.5 pt-2 border-t border-slate-800 overflow-x-auto">
          <span className="text-[11px] text-slate-400 uppercase font-semibold mr-1">
            Canonical Targets:
          </span>
          {scenarioShortcuts.map((scenId) => {
            const scenData = SCENARIO_RECEIVER_EVIDENCE[scenId];
            const isSelected = selectedScenarioId === scenId;
            return (
              <button
                key={scenId}
                type="button"
                onClick={() => handleSelectScenario(scenId)}
                className={`px-2.5 py-1 rounded-md text-xs font-mono transition border flex items-center gap-1.5 ${
                  isSelected
                    ? 'bg-cyan-950 border-cyan-500 text-cyan-300 font-bold ring-1 ring-cyan-500/50'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                }`}
              >
                <span>{`${scenId}:`}</span>
                <span className="text-[11px]">{scenData.accountId}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Target Account Header Strip & Verdict Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <span className="font-mono text-base font-bold text-white">{activeAccount}</span>
              <span className="font-mono text-[10px] uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                {evidenceData.network}
              </span>
              {selectedScenarioId !== 'CUSTOM' && (
                <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                  {selectedScenarioId} Preset
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400">
              {evidenceData.historical.isContract
                ? 'Smart Contract Account'
                : 'Externally Owned Account (EOA)'}
              {' • '}
              {evidenceData.historical.accountAgeDays >= 1
                ? `${evidenceData.historical.accountAgeDays.toFixed(0)} days active`
                : 'Freshly created (< 24h)'}
            </p>
          </div>

          <div className="flex items-center gap-4">
            <div className="text-right">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
                Policy Decision
              </span>
              <DecisionBadge decision={evidenceData.decision} size="md" />
            </div>
          </div>
        </div>

        {/* Active Block Warning Banner (if blocked) */}
        {evidenceData.isBlocked && (
          <div className="p-3.5 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-start gap-2.5">
            <BanIcon size={18} className="text-rose-400 shrink-0 mt-0.5" />
            <div className="space-y-0.5">
              <span className="font-bold text-rose-200 block">
                {`ACTIVE HARD BLOCK IN EFFECT (Blocklist Revision #${evidenceData.blocklistRevision ?? 7})`}
              </span>
              <p className="text-rose-300">{evidenceData.blockReason}</p>
              <span className="text-[10px] text-rose-400 block pt-0.5 font-mono">
                Security Invariant: Guard SDK aborts all execution attempts before signing
                (signed=false, submitted=false).
              </span>
            </div>
          </div>
        )}

        {/* Risk Meter & Indicators */}
        <RiskMeter score={evidenceData.riskScore} />
      </div>

      {/* Historical Observations & Contract Upgrade Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="font-semibold text-white text-sm flex items-center gap-2">
            <ShieldAlertIcon size={16} className="text-cyan-400" />
            Historical Observations & Contract Code Auditing
          </h3>
          {evidenceData.historical.codeHashChanged ? (
            <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-950 border border-amber-700 text-amber-300 animate-pulse">
              CODE_CHANGED: BYTECODE UPGRADED
            </span>
          ) : evidenceData.historical.isContract ? (
            <span className="px-2.5 py-0.5 rounded text-[11px] font-mono bg-emerald-950 border border-emerald-800 text-emerald-300">
              BYTECODE VERIFIED
            </span>
          ) : (
            <span className="px-2.5 py-0.5 rounded text-[11px] font-mono bg-slate-800 border border-slate-700 text-slate-300">
              EOA / UNCONTRACTED
            </span>
          )}
        </div>

        {/* Contract Code Hash Comparison (when upgraded) */}
        {evidenceData.historical.codeHashChanged ? (
          <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-800 space-y-3">
            <div className="flex items-start gap-2.5">
              <AlertTriangleIcon size={18} className="text-amber-400 shrink-0 mt-0.5" />
              <div className="text-xs text-amber-200">
                <span className="font-bold text-amber-300 block">
                  Contract Bytecode Upgrade Detected (Policy Trigger: S7)
                </span>
                <p>{evidenceData.historical.upgradeReason}</p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
              {/* Previous Code Hash */}
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-400 block text-[10px] uppercase">
                  Previous Bytecode Hash (v1.0.0)
                </span>
                <span className="text-slate-300 break-all text-[11px] line-through opacity-75">
                  {evidenceData.historical.previousCodeHash}
                </span>
                <span className="text-[10px] text-slate-400 block pt-1">
                  Deployed: {evidenceData.historical.deploymentTimestamp} (32.4 KB)
                </span>
              </div>

              {/* Current Code Hash */}
              <div className="p-3 rounded-lg bg-slate-950 border border-amber-700 ring-1 ring-amber-500/40 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-amber-300 block text-[10px] uppercase font-bold">
                    Active Upgraded Bytecode Hash (v2.0.0)
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      handleCopy(evidenceData.historical.currentCodeHash || '', 'newHash')
                    }
                    className="p-1 rounded bg-slate-800 text-slate-300 hover:text-white"
                    title="Copy code hash"
                  >
                    {copiedHash === 'newHash' ? (
                      <CheckIcon size={12} className="text-emerald-400" />
                    ) : (
                      <CopyIcon size={12} />
                    )}
                  </button>
                </div>
                <span className="text-amber-400 break-all text-[11px] font-bold">
                  {evidenceData.historical.currentCodeHash}
                </span>
                <span className="text-[10px] text-amber-300 block pt-1">
                  Upgraded: {evidenceData.historical.upgradeTimestamp} (48.2 KB, +15.8 KB)
                </span>
              </div>
            </div>
          </div>
        ) : evidenceData.historical.isContract ? (
          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-1">
            <span className="text-slate-400 block text-[10px]">Active Contract Bytecode Hash</span>
            <div className="flex items-center justify-between">
              <span className="text-slate-200 break-all text-[11px]">
                {evidenceData.historical.currentCodeHash}
              </span>
              <button
                type="button"
                onClick={() => handleCopy(evidenceData.historical.currentCodeHash || '', 'curHash')}
                className="p-1 ml-2 rounded bg-slate-800 text-slate-300 hover:text-white shrink-0"
              >
                {copiedHash === 'curHash' ? (
                  <CheckIcon size={12} className="text-emerald-400" />
                ) : (
                  <CopyIcon size={12} />
                )}
              </button>
            </div>
            {evidenceData.historical.bytecodeSizeBytes && (
              <span className="text-[10px] text-slate-400 block pt-1">
                Size: {(evidenceData.historical.bytecodeSizeBytes / 1024).toFixed(1)} KB • Deployed:{' '}
                {evidenceData.historical.deploymentTimestamp}
              </span>
            )}
          </div>
        ) : null}

        {/* Observations Metric Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-400 block text-[10px]">Account First Seen</span>
            <span className="font-mono text-slate-200 font-semibold">
              {evidenceData.historical.firstSeenTimestamp}
            </span>
          </div>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-400 block text-[10px]">Active Age</span>
            <span className="font-mono text-emerald-400 font-semibold">
              {evidenceData.historical.accountAgeDays >= 1
                ? `${evidenceData.historical.accountAgeDays.toFixed(0)} Days`
                : '< 24 Hours'}
            </span>
          </div>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-400 block text-[10px]">Prior Interactions</span>
            <span className="font-mono text-cyan-400 font-semibold">
              {`${evidenceData.historical.interactionCount} Finalized`}
            </span>
          </div>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-400 block text-[10px]">Last Interaction</span>
            <span className="font-mono text-slate-200 font-semibold truncate block">
              {evidenceData.historical.lastInteractionTimestamp || 'None'}
            </span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Chronological Audit Trail & Reports */}
        <div className="lg:col-span-6 space-y-6">
          {/* Chronological Audit Trail */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-semibold text-white text-sm">Chronological Audit Trail</h3>
              <div className="flex items-center gap-1 text-[10px] font-mono">
                <button
                  type="button"
                  onClick={() => setTimelineFilter('all')}
                  className={`px-2 py-0.5 rounded ${timelineFilter === 'all' ? 'bg-cyan-900 text-cyan-200' : 'bg-slate-800 text-slate-400'}`}
                >
                  All
                </button>
                <button
                  type="button"
                  onClick={() => setTimelineFilter('contract')}
                  className={`px-2 py-0.5 rounded ${timelineFilter === 'contract' ? 'bg-cyan-900 text-cyan-200' : 'bg-slate-800 text-slate-400'}`}
                >
                  Code
                </button>
                <button
                  type="button"
                  onClick={() => setTimelineFilter('reports')}
                  className={`px-2 py-0.5 rounded ${timelineFilter === 'reports' ? 'bg-cyan-900 text-cyan-200' : 'bg-slate-800 text-slate-400'}`}
                >
                  Reports
                </button>
              </div>
            </div>

            <div className="relative border-l border-slate-800 ml-3 space-y-5">
              {filteredEvents.map((evt) => (
                <div key={evt.id} className="relative pl-6">
                  <span
                    className={`absolute -left-1.5 top-1 w-3 h-3 rounded-full ring-4 ring-slate-900 ${
                      evt.type === 'creation'
                        ? 'bg-cyan-500'
                        : evt.type === 'deployment'
                          ? 'bg-amber-400'
                          : evt.type === 'report'
                            ? 'bg-rose-500'
                            : 'bg-emerald-400'
                    }`}
                  />
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-semibold text-slate-200">{evt.title}</h4>
                    <span className="font-mono text-[10px] text-slate-400">
                      {new Date(evt.timestamp).toLocaleDateString()}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{evt.description}</p>
                  {evt.txHash && (
                    <div className="mt-1 flex items-center gap-1.5">
                      <span className="font-mono text-[10px] text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800 truncate max-w-xs">
                        tx: {evt.txHash}
                      </span>
                    </div>
                  )}
                  {evt.codeHash && (
                    <span className="inline-block mt-1 font-mono text-[10px] text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800">
                      code: {evt.codeHash}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Report Audit Trail Panel */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="font-semibold text-white text-sm">Report Audit Trail</h3>
                <span className="text-[11px] text-slate-400">
                  {`${evidenceData.dependenceGroup ? evidenceData.dependenceGroup.rawCount : evidenceData.reports.length} total allegation(s) on file`}
                </span>
              </div>
              <div className="text-right">
                <span className="text-[10px] text-slate-400 block">Effective Weight</span>
                <span className="font-mono font-bold text-xs text-emerald-400">
                  {evidenceData.dependenceGroup
                    ? `${evidenceData.dependenceGroup.effectiveWeight.toFixed(1)} (Capped)`
                    : `${evidenceData.reports.reduce((acc, r) => acc + (r.effectiveWeight ?? 1.0), 0).toFixed(1)}`}
                </span>
              </div>
            </div>

            {evidenceData.reports.length === 0 ? (
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-center space-y-1">
                <ShieldCheckIcon size={24} className="text-emerald-400 mx-auto" />
                <h4 className="text-xs font-semibold text-white">Clean Report Audit Trail</h4>
                <p className="text-[11px] text-slate-400">
                  No adverse reports, phishing allegations, or drain claims recorded against this
                  counterparty.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {evidenceData.reports.map((rep) => {
                  const catClass = CATEGORY_STYLES[rep.category] || CATEGORY_STYLES.other;
                  const statClass = STATUS_STYLES[rep.status] || STATUS_STYLES.submitted;

                  return (
                    <div
                      key={rep.id}
                      className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono border font-semibold uppercase ${catClass}`}
                          >
                            {rep.category}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono border uppercase ${statClass}`}
                          >
                            {rep.status}
                          </span>
                        </div>
                        <span className="font-mono text-[10px] text-slate-400">
                          {`Weight: ${(rep.effectiveWeight ?? 1.0).toFixed(2)}`}
                        </span>
                      </div>

                      <p className="text-xs text-slate-300">{rep.description}</p>

                      <div className="pt-2 border-t border-slate-900 grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-[10px] font-mono text-slate-400">
                        <div>
                          <span>Reporter: </span>
                          <span className="text-slate-300">{rep.reporterId}</span>
                        </div>
                        <div>
                          <span>Issued: </span>
                          <span className="text-slate-300">
                            {new Date(rep.issuedAt).toLocaleDateString()}
                          </span>
                        </div>
                      </div>

                      {/* Evidence Content Hashes & References */}
                      {(rep.evidenceHashes.length > 0 || rep.txReferences.length > 0) && (
                        <div className="pt-2 space-y-1 text-[10px] font-mono">
                          {rep.evidenceHashes.map((h) => (
                            <div
                              key={h}
                              className="flex items-center justify-between bg-slate-900 p-1.5 rounded border border-slate-800"
                            >
                              <span className="text-cyan-400 truncate max-w-[240px]">{`sha256:${h}`}</span>
                              <button
                                type="button"
                                onClick={() => handleCopy(h, h)}
                                className="text-slate-400 hover:text-white p-0.5"
                                title="Copy content hash"
                              >
                                {copiedHash === h ? (
                                  <CheckIcon size={10} className="text-emerald-400" />
                                ) : (
                                  <CopyIcon size={10} />
                                )}
                              </button>
                            </div>
                          ))}
                          {rep.txReferences.map((ref) => (
                            <span
                              key={ref}
                              className="inline-block bg-slate-900 px-2 py-0.5 rounded border border-slate-800 text-slate-300 mr-1"
                            >
                              {ref}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Bounded Graph Traversal & Heuristic Explanations */}
        <div className="lg:col-span-6 space-y-6">
          {/* Bounded Graph Traversal Bounds Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                <ActivityIcon size={16} className="text-cyan-400" />
                Bounded Graph Traversal Status
              </h3>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                  evidenceData.coverage.truncated
                    ? 'bg-amber-950 border-amber-800 text-amber-300'
                    : 'bg-emerald-950 border-emerald-800 text-emerald-300'
                }`}
              >
                {`Truncated: ${evidenceData.coverage.truncated ? 'TRUE' : 'FALSE'}`}
              </span>
            </div>

            <div className="grid grid-cols-3 gap-2 text-center text-xs">
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">Visited Nodes</span>
                <span className="font-mono font-bold text-slate-200">
                  {`${evidenceData.coverage.accountsVisited} / 100 max`}
                </span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">Edges Traversed</span>
                <span className="font-mono font-bold text-slate-200">
                  {`${evidenceData.coverage.edgesTraversed} / 500 max`}
                </span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">Rolling Window</span>
                <span className="font-mono font-bold text-slate-200">
                  {`${evidenceData.coverage.windowDays} Days (2 Hops)`}
                </span>
              </div>
            </div>
          </div>

          {/* Relational Funding Connections Breakdown */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <h3 className="font-semibold text-white text-sm border-b border-slate-800 pb-2">
              Observed Inbound Funding Lineage (2 Hops)
            </h3>
            {evidenceData.fundingConnections.length === 0 ? (
              <p className="text-xs text-slate-400">
                No funding edges observed in current rolling window.
              </p>
            ) : (
              <div className="space-y-2">
                {evidenceData.fundingConnections.map((fc, idx) => (
                  <div
                    key={`${fc.source}-${fc.target}-${idx}`}
                    className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-cyan-950 border border-cyan-800 text-cyan-300">
                          {`Hop ${fc.hopLevel}`}
                        </span>
                        <span className="text-slate-200 font-bold">{fc.source}</span>
                        <span className="text-slate-500">→</span>
                        <span className="text-slate-300">{fc.target}</span>
                      </div>
                      <span className="text-emerald-400 font-semibold">{`${fc.amountNear} NEAR`}</span>
                    </div>
                    {fc.description && (
                      <p className="text-[11px] text-slate-400 pt-0.5">{fc.description}</p>
                    )}
                    <span className="text-[10px] text-slate-500 block">{`tx: ${fc.txHash}`}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Circular Loop Explanation Card (Conditional: S5) */}
          {evidenceData.circularFlow.detected && (
            <div className="bg-slate-900 border border-amber-800 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                  <AlertTriangleIcon size={16} className="text-amber-400" />
                  Circular Flow Detection (CIRCULAR_ACTIVITY)
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950 border border-amber-800 text-amber-300">
                  {`Score: ${evidenceData.circularFlow.score}/100`}
                </span>
              </div>
              <p className="text-xs text-amber-200">{evidenceData.circularFlow.discountPenalty}</p>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-2">
                <div className="flex justify-between text-slate-400">
                  <span>Circular Volume Ratio:</span>
                  <span className="text-amber-400 font-bold">{`${evidenceData.circularFlow.circularVolumePercent}%`}</span>
                </div>
                <div>
                  <span className="text-slate-400 block mb-1">Detected Closed Cycle Path:</span>
                  {evidenceData.circularFlow.cyclePaths?.map((path) => (
                    <div
                      key={path}
                      className="p-2 rounded bg-slate-900 border border-slate-800 text-cyan-300 text-[11px]"
                    >
                      {path}
                    </div>
                  ))}
                </div>
                <div>
                  <span className="text-slate-400 block mb-1">Participating Ring Accounts:</span>
                  <div className="flex flex-wrap gap-1">
                    {evidenceData.circularFlow.ringAccounts.map((acc) => (
                      <span
                        key={acc}
                        className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300 text-[10px]"
                      >
                        {acc}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Sybil Clustering & Weight Capping Card (Conditional: S4) */}
          {evidenceData.dependenceGroup && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <h3 className="font-semibold text-white text-sm">
                  Sybil Clustering & Weight Capping
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950 border border-amber-800 text-amber-300">
                  {`Capped: ${evidenceData.dependenceGroup.effectiveWeight.toFixed(1)} Max`}
                </span>
              </div>
              <p className="text-xs text-slate-300">
                {evidenceData.dependenceGroup.discountReason}
              </p>
              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-2">
                <div className="flex justify-between text-slate-400">
                  <span>Common Progenitor Funder:</span>
                  <span className="text-amber-400 font-bold">
                    {evidenceData.dependenceGroup.commonFunder}
                  </span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Raw Allegations Count:</span>
                  <span className="text-slate-200">{`${evidenceData.dependenceGroup.rawCount} accounts`}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Effective Capped Weight:</span>
                  <span className="text-emerald-400 font-bold">
                    {`${evidenceData.dependenceGroup.effectiveWeight.toFixed(1)} (${evidenceData.dependenceGroup.discountFactor.toFixed(2)} per report)`}
                  </span>
                </div>
                <div className="pt-2 border-t border-slate-900 text-[10px] text-slate-400">
                  <span>Member Reporters: </span>
                  <span className="text-slate-300">
                    {evidenceData.dependenceGroup.memberReporters.slice(0, 5).join(', ')}
                    {evidenceData.dependenceGroup.memberReporters.length > 5 &&
                      ` + ${evidenceData.dependenceGroup.memberReporters.length - 5} more`}
                  </span>
                </div>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-400">
                <span className="font-semibold text-slate-300">Security Invariant: </span>
                Coordinated Sybil floods cannot trigger a hard block without authenticated human
                reviewer action.
              </div>
            </div>
          )}

          {/* Common Faucet Exemption Control Card */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-start gap-3">
            <div
              className={`p-2 rounded-lg border ${
                evidenceData.faucetExemption.isExempted
                  ? 'bg-emerald-950 border-emerald-800 text-emerald-400'
                  : 'bg-slate-950 border-slate-800 text-slate-400'
              }`}
            >
              <ShieldCheckIcon size={20} />
            </div>
            <div className="space-y-0.5">
              <h4
                className={`text-xs font-semibold ${
                  evidenceData.faucetExemption.isExempted ? 'text-emerald-300' : 'text-slate-300'
                }`}
              >
                {evidenceData.faucetExemption.isExempted
                  ? 'Common Faucet Exemption Active'
                  : 'No Faucet Exemption Applied'}
              </h4>
              <p className="text-xs text-slate-400">{evidenceData.faucetExemption.notes}</p>
              {evidenceData.faucetExemption.faucetAccountId && (
                <span className="inline-block mt-1 font-mono text-[10px] text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800">
                  {`exempted: ${evidenceData.faucetExemption.faucetAccountId}`}
                </span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EvidenceTimeline;
