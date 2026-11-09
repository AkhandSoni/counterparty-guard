import type { ScenarioId } from '@counterparty-guard/shared/demo';
import type React from 'react';
import { useState } from 'react';
import { type ActionParams, formatDisplayPermitHash, mockAdapter } from '../adapters/mockAdapter';
import { DecisionBadge } from '../components/Badge';
import { CodeBlock } from '../components/CodeBlock';
import {
  AlertTriangleIcon,
  CheckCircleIcon,
  CheckIcon,
  CopyIcon,
  ShieldAlertIcon,
} from '../components/Icons';
import { RiskMeter } from '../components/RiskMeter';
import type { CheckActionParams, PendingWarningContext } from '../types';

export interface ReasonCodeMeta {
  label: string;
  severity: 'critical' | 'warn' | 'info' | 'error';
  badgeStyle: string;
  description: string;
}

export const REASON_CODE_METADATA: Record<string, ReasonCodeMeta> = {
  ACTIVE_BLOCK: {
    label: 'ACTIVE_BLOCK',
    severity: 'critical',
    badgeStyle: 'bg-rose-950/70 border-rose-700 text-rose-300',
    description: 'Counterparty is explicitly listed on the reviewed blocklist.',
  },
  REVIEWED_BLOCKLIST_MATCH: {
    label: 'REVIEWED_BLOCKLIST_MATCH',
    severity: 'critical',
    badgeStyle: 'bg-rose-950/70 border-rose-700 text-rose-300',
    description: 'Matches active blocklist revision confirmed by human moderator.',
  },
  RECENT_DEPLOYMENT: {
    label: 'RECENT_DEPLOYMENT',
    severity: 'warn',
    badgeStyle: 'bg-amber-950/70 border-amber-700 text-amber-300',
    description: 'Receiver account or contract deployed < 24h ago.',
  },
  UNKNOWN_AGE: {
    label: 'UNKNOWN_AGE',
    severity: 'warn',
    badgeStyle: 'bg-amber-950/70 border-amber-700 text-amber-300',
    description: 'Account age cannot be independently corroborated.',
  },
  CIRCULAR_ACTIVITY: {
    label: 'CIRCULAR_ACTIVITY',
    severity: 'warn',
    badgeStyle: 'bg-amber-950/70 border-amber-700 text-amber-300',
    description: 'Reciprocal or cyclic money flows detected within counterparty funding graph.',
  },
  DEPENDENT_REPORTS: {
    label: 'DEPENDENT_REPORTS',
    severity: 'warn',
    badgeStyle: 'bg-amber-950/70 border-amber-700 text-amber-300',
    description:
      'Multiple reports clustered into single group due to common funder; weight capped.',
  },
  COMMON_FAUCET_EXEMPTED: {
    label: 'COMMON_FAUCET_EXEMPTED',
    severity: 'info',
    badgeStyle: 'bg-cyan-950/70 border-cyan-700 text-cyan-300',
    description: 'Shared funding from known faucet exempted from clustering penalties.',
  },
  CODE_CHANGED: {
    label: 'CODE_CHANGED',
    severity: 'warn',
    badgeStyle: 'bg-amber-950/70 border-amber-700 text-amber-300',
    description: 'Contract bytecode hash changed since prior interaction; requires re-evaluation.',
  },
  INCOMPLETE_HISTORY: {
    label: 'INCOMPLETE_HISTORY',
    severity: 'error',
    badgeStyle: 'bg-purple-950/70 border-purple-700 text-purple-300',
    description: 'Mandatory upstream provider timed out or returned incomplete history.',
  },
  MANDATORY_SOURCE_UNAVAILABLE: {
    label: 'MANDATORY_SOURCE_UNAVAILABLE',
    severity: 'error',
    badgeStyle: 'bg-purple-950/70 border-purple-700 text-purple-300',
    description: 'Mandatory reputation or graph data source is currently unavailable.',
  },
  POLICY_LIMIT_EXCEEDED: {
    label: 'POLICY_LIMIT_EXCEEDED',
    severity: 'warn',
    badgeStyle: 'bg-amber-950/70 border-amber-700 text-amber-300',
    description: 'Requested transfer amount exceeds autonomous agent policy threshold.',
  },
};

interface CheckActionViewProps {
  onNavigateToApprovals?: (context?: PendingWarningContext) => void;
}

export const CheckActionView: React.FC<CheckActionViewProps> = ({ onNavigateToApprovals }) => {
  const initialResult = mockAdapter.evaluateScenario('S1');

  const [selectedScenarioId, setSelectedScenarioId] = useState<ScenarioId | 'CUSTOM'>('S1');
  const [params, setParams] = useState<CheckActionParams>({
    network: 'testnet',
    vaultAccountId: initialResult.params.vaultAccountId,
    receiverAccountId: initialResult.params.receiverAccountId,
    actionKind: initialResult.params.actionKind,
    amountNear: initialResult.params.amountNear,
    methodName: initialResult.params.methodName,
    argsJson: initialResult.params.argsJson,
  });
  const [verdict, setVerdict] = useState(initialResult.verdict);
  const [canonicalResponse, setCanonicalResponse] = useState(initialResult.canonicalResponse);
  const [isModified, setIsModified] = useState<boolean>(false);
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);
  const [showJson, setShowJson] = useState<boolean>(false);

  const scenarios = mockAdapter.listScenarios();
  const currentScenario =
    selectedScenarioId !== 'CUSTOM' ? mockAdapter.getScenario(selectedScenarioId) : null;

  const handleSelectScenario = (id: ScenarioId) => {
    setSelectedScenarioId(id);
    const result = mockAdapter.evaluateScenario(id);
    setParams({
      network: 'testnet',
      vaultAccountId: result.params.vaultAccountId,
      receiverAccountId: result.params.receiverAccountId,
      actionKind: result.params.actionKind,
      amountNear: result.params.amountNear,
      methodName: result.params.methodName,
      argsJson: result.params.argsJson,
    });
    setVerdict(result.verdict);
    setCanonicalResponse(result.canonicalResponse);
    setIsModified(false);
    setValidationError(null);
  };

  const handleParamChange = (field: keyof CheckActionParams, value: string) => {
    const updated = { ...params, [field]: value };
    setParams(updated);

    if (selectedScenarioId !== 'CUSTOM') {
      const preset = mockAdapter.getScenario(selectedScenarioId);
      if (preset) {
        const matchesPreset =
          updated.vaultAccountId === preset.params.vaultAccountId &&
          updated.receiverAccountId === preset.params.receiverAccountId &&
          updated.actionKind === preset.params.actionKind &&
          updated.amountNear === preset.params.amountNear &&
          (updated.methodName || '') === (preset.params.methodName || '') &&
          (updated.argsJson || '') === (preset.params.argsJson || '');
        setIsModified(!matchesPreset);
      }
    } else {
      setIsModified(true);
    }
  };

  const handleRevertPreset = () => {
    if (selectedScenarioId !== 'CUSTOM') {
      handleSelectScenario(selectedScenarioId);
    } else {
      handleSelectScenario('S1');
    }
  };

  const handleEvaluate = (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);

    // Client-side input validation
    if (!params.receiverAccountId || params.receiverAccountId.trim().length < 2) {
      setValidationError('Receiver account ID is required (min 2 characters).');
      return;
    }
    const parsedAmount = Number.parseFloat(params.amountNear);
    if (Number.isNaN(parsedAmount) || parsedAmount < 0) {
      setValidationError('Amount must be a valid positive NEAR number.');
      return;
    }
    if (params.actionKind === 'contract_call' && params.argsJson) {
      try {
        JSON.parse(params.argsJson);
      } catch {
        setValidationError('Contract arguments must be valid JSON.');
        return;
      }
    }

    setIsEvaluating(true);
    try {
      const actionParams: ActionParams = {
        network: params.network,
        vaultAccountId: params.vaultAccountId,
        receiverAccountId: params.receiverAccountId,
        actionKind: params.actionKind,
        amountNear: params.amountNear,
        methodName: params.methodName,
        argsJson: params.argsJson,
      };

      const result = mockAdapter.evaluate(actionParams);
      setVerdict(result.verdict);
      setCanonicalResponse(result.canonicalResponse);

      if (result.matchedScenarioId !== 'CUSTOM') {
        setSelectedScenarioId(result.matchedScenarioId);
        const preset = mockAdapter.getScenario(result.matchedScenarioId);
        if (preset) {
          const matches =
            params.vaultAccountId === preset.params.vaultAccountId &&
            params.receiverAccountId === preset.params.receiverAccountId &&
            params.actionKind === preset.params.actionKind &&
            params.amountNear === preset.params.amountNear &&
            (params.methodName || '') === (preset.params.methodName || '') &&
            (params.argsJson || '') === (preset.params.argsJson || '');
          setIsModified(!matches);
        }
      } else {
        setSelectedScenarioId('CUSTOM');
        setIsModified(true);
      }
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleCopyHash = (hash: string | null) => {
    if (!hash) return;
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Scenario Quick Selector Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div className="flex items-center justify-between mb-2.5">
          <h2 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Deterministic Scenario Quick Selector (S1 – S10)
          </h2>
          {isModified && (
            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-950/80 text-amber-300 border border-amber-800">
              Parameters Modified
            </span>
          )}
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-5 md:grid-cols-10 gap-1.5">
          {scenarios.map((scen) => (
            <button
              key={scen.id}
              type="button"
              onClick={() => handleSelectScenario(scen.id)}
              className={`p-2 rounded-lg border text-left transition flex flex-col justify-between ${
                selectedScenarioId === scen.id
                  ? 'bg-cyan-950/80 border-cyan-500 ring-1 ring-cyan-500'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-white">{scen.id}</span>
                <span
                  className={`w-2 h-2 rounded-full ${
                    scen.expectedDecision === 'allow'
                      ? 'bg-emerald-400'
                      : scen.expectedDecision === 'warn'
                        ? 'bg-amber-400'
                        : 'bg-rose-400'
                  }`}
                />
              </div>
              <span className="text-[10px] text-slate-400 truncate mt-1">
                {scen.expectedDecision.toUpperCase()}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Scenario Context Card */}
      {currentScenario ? (
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                {currentScenario.id}
              </span>
              <h3 className="font-semibold text-sm text-white">{currentScenario.name}</h3>
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                Expected: {currentScenario.expectedDecision}
              </span>
              {isModified && (
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-950/70 text-amber-300 border border-amber-800">
                  Form Edited
                </span>
              )}
            </div>
            <p className="text-xs text-slate-300">{currentScenario.description}</p>
          </div>
          {isModified && (
            <button
              type="button"
              onClick={handleRevertPreset}
              className="shrink-0 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700 transition"
            >
              Revert to Preset
            </button>
          )}
        </div>
      ) : (
        <div className="bg-slate-900/90 border border-cyan-800/60 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                CUSTOM
              </span>
              <h3 className="font-semibold text-sm text-white">Custom Parameter Evaluation</h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800">
                Dynamic Heuristic Mode
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1">
              Evaluating arbitrary user parameters using defensive heuristic security rules.
            </p>
          </div>
          <button
            type="button"
            onClick={handleRevertPreset}
            className="shrink-0 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700 transition"
          >
            Reset to S1
          </button>
        </div>
      )}

      {/* Validation Error Banner */}
      {validationError && (
        <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangleIcon size={16} className="text-rose-400 shrink-0" />
          <span>{validationError}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Action Parameters Form */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="font-semibold text-white text-sm">Proposed Transaction Action</h3>
              <p className="text-xs text-slate-400">Evaluate receiver counterparty risk</p>
            </div>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300">
              {params.network}
            </span>
          </div>

          <form onSubmit={handleEvaluate} className="space-y-3.5 text-xs">
            <div>
              <label htmlFor="vault-account-id" className="block text-slate-400 mb-1">
                Vault Account ID
              </label>
              <input
                id="vault-account-id"
                type="text"
                value={params.vaultAccountId}
                onChange={(e) => handleParamChange('vaultAccountId', e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label htmlFor="receiver-account-id" className="block text-slate-400 mb-1">
                Receiver Account ID
              </label>
              <input
                id="receiver-account-id"
                type="text"
                value={params.receiverAccountId}
                onChange={(e) => handleParamChange('receiverAccountId', e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label htmlFor="action-type-select" className="block text-slate-400 mb-1">
                  Action Type
                </label>
                <select
                  id="action-type-select"
                  value={params.actionKind}
                  onChange={(e) =>
                    handleParamChange(
                      'actionKind',
                      e.target.value as 'transfer_near' | 'contract_call',
                    )
                  }
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
                >
                  <option value="transfer_near">transfer_near</option>
                  <option value="contract_call">contract_call</option>
                </select>
              </div>

              <div>
                <label htmlFor="amount-near-input" className="block text-slate-400 mb-1">
                  Amount (NEAR)
                </label>
                <input
                  id="amount-near-input"
                  type="text"
                  value={params.amountNear}
                  onChange={(e) => handleParamChange('amountNear', e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            {params.actionKind === 'contract_call' && (
              <>
                <div>
                  <label htmlFor="method-name-input" className="block text-slate-400 mb-1">
                    Method Name
                  </label>
                  <input
                    id="method-name-input"
                    type="text"
                    value={params.methodName || ''}
                    onChange={(e) => handleParamChange('methodName', e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label htmlFor="args-json-input" className="block text-slate-400 mb-1">
                    Arguments (JSON)
                  </label>
                  <input
                    id="args-json-input"
                    type="text"
                    value={params.argsJson || ''}
                    onChange={(e) => handleParamChange('argsJson', e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              </>
            )}

            <button
              type="submit"
              disabled={isEvaluating}
              className="w-full mt-2 py-2.5 px-4 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-800 text-white font-medium transition shadow-sm flex items-center justify-center gap-2"
            >
              {isEvaluating ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Evaluating Policy...</span>
                </>
              ) : (
                <span>Re-Evaluate Action</span>
              )}
            </button>
          </form>
        </div>

        {/* Right Column: Assessment Verdict Card */}
        <div className="lg:col-span-7 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <span className="text-xs text-slate-400">Evaluation Decision</span>
                <div className="mt-1">
                  <DecisionBadge decision={verdict.decision} size="lg" />
                </div>
                {verdict.decision === 'warn' && onNavigateToApprovals && verdict.permit && (
                  <button
                    type="button"
                    onClick={() =>
                      onNavigateToApprovals({
                        permitHash: verdict.permit?.permitHash || '',
                        vaultAccountId: params.vaultAccountId,
                        receiverAccountId: params.receiverAccountId,
                        amountNear: params.amountNear,
                        reasonCodes: verdict.reasonCodes,
                      })
                    }
                    className="mt-2 text-xs text-amber-400 hover:text-amber-300 font-semibold underline flex items-center gap-1"
                  >
                    View Required Owner Warning Approval Instructions →
                  </button>
                )}
              </div>

              <div className="text-right">
                <span className="text-xs text-slate-400">Source & Freshness</span>
                <p className="font-mono text-xs text-slate-200">{verdict.freshness}</p>
                <span className="inline-block px-2 py-0.5 mt-1 rounded text-[10px] font-mono bg-slate-800 text-cyan-300">
                  mode: {verdict.sourceMode}
                </span>
              </div>
            </div>

            {/* Risk Indicator */}
            <RiskMeter score={verdict.riskScore} />

            {/* Reason Codes */}
            <div>
              <span className="text-xs font-semibold text-slate-300 block mb-2">
                Machine Reason Codes
              </span>
              {verdict.reasonCodes.length === 0 ? (
                <div className="p-2.5 rounded-lg bg-emerald-950/40 border border-emerald-900 text-emerald-300 text-xs flex items-center gap-2">
                  <CheckCircleIcon size={16} />
                  <span>No security flags or adverse allegations detected.</span>
                </div>
              ) : (
                <div className="space-y-2">
                  {verdict.reasonCodes.map((code) => {
                    const meta = REASON_CODE_METADATA[code] || {
                      label: code,
                      severity: 'warn',
                      badgeStyle: 'bg-slate-800 border-slate-700 text-slate-300',
                      description: 'Security indicator flagged during counterparty evaluation.',
                    };

                    return (
                      <div
                        key={code}
                        className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs flex items-start gap-2.5"
                      >
                        <span
                          className={`font-mono px-2 py-0.5 rounded border font-semibold text-[10px] ${meta.badgeStyle}`}
                        >
                          {code}
                        </span>
                        <span className="text-slate-300 text-xs">{meta.description}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Cryptographic Permit Card */}
            <div className="border-t border-slate-800 pt-4">
              <span className="text-xs font-semibold text-slate-300 block mb-2">
                Cryptographic Permit
              </span>
              {verdict.permit ? (
                <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs space-y-2.5">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-slate-400">
                    <span>Permit Digest:</span>
                    <div className="flex items-center gap-1.5">
                      <span
                        className="text-cyan-400 truncate max-w-[200px] sm:max-w-xs font-mono"
                        title={`Canonical 64 hex: ${verdict.permit.permitHash}`}
                      >
                        {formatDisplayPermitHash(verdict.permit.permitHash)}
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopyHash(verdict.permit?.permitHash || null)}
                        className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
                        title="Copy canonical 64 hex permit hash"
                      >
                        {copiedHash ? (
                          <CheckIcon size={12} className="text-emerald-400" />
                        ) : (
                          <CopyIcon size={12} />
                        )}
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[11px] text-slate-400 pt-1 border-t border-slate-900">
                    <div>
                      <span>Nonce: </span>
                      <span className="text-slate-200">{verdict.permit.nonce}</span>
                    </div>
                    <div>
                      <span>Revision: </span>
                      <span className="text-slate-200">#{verdict.permit.policyRevision}</span>
                    </div>
                    <div>
                      <span>Validity: </span>
                      <span className="text-slate-200">~15 mins</span>
                    </div>
                  </div>

                  <div className="text-[10px] text-slate-400">
                    <span>Signed by: </span>
                    <span className="text-slate-300">Counterparty Guard Authority (Ed25519)</span>
                  </div>

                  {verdict.decision === 'warn' && onNavigateToApprovals && (
                    <div className="pt-2 border-t border-slate-900 mt-2">
                      <button
                        type="button"
                        onClick={() =>
                          onNavigateToApprovals({
                            permitHash: verdict.permit?.permitHash || '',
                            vaultAccountId: params.vaultAccountId,
                            receiverAccountId: params.receiverAccountId,
                            amountNear: params.amountNear,
                            reasonCodes: verdict.reasonCodes,
                          })
                        }
                        className="text-xs text-amber-400 hover:text-amber-300 font-semibold underline flex items-center gap-1"
                      >
                        View Required Owner Warning Approval Instructions →
                      </button>
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-900 text-rose-300 text-xs flex items-center gap-2">
                  <ShieldAlertIcon size={18} />
                  <div>
                    <span className="font-semibold block">
                      Permit refused by policy: signing disabled
                    </span>
                    <span className="text-[11px] text-rose-400">
                      Transaction cannot be executed. Guard SDK aborts before signing.
                    </span>
                  </div>
                </div>
              )}
            </div>

            {/* JSON Inspector Toggle */}
            <div className="pt-2">
              <button
                type="button"
                onClick={() => setShowJson(!showJson)}
                className="text-xs text-slate-400 hover:text-slate-200 underline"
              >
                {showJson ? 'Hide Raw Payloads' : 'Inspect Raw Check Payloads (JSON)'}
              </button>
              {showJson && (
                <div className="mt-2">
                  <CodeBlock
                    code={JSON.stringify({ params, canonicalResponse, verdict }, null, 2)}
                    title="Check Payloads & Canonical Response (JSON)"
                  />
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
