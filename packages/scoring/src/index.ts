import {
  actionSchema, policySnapshotSchema, receiverEvidenceSchema, reputationSnapshotSchema,
  memoArgumentsSchema, scoreResultSchema, GuardError,
  type Action, type ReceiverEvidence, type ReputationSnapshot, type PolicySnapshot,
  type ScoreResult, type ReasonCode, type FinalizedAgentHistory,
} from '@counterparty-guard/shared';

export interface ScoringInput {
  action: Action;
  evidence: ReceiverEvidence;
  reputation: ReputationSnapshot;
  policy: PolicySnapshot;
  history: FinalizedAgentHistory;
  now: number;
}

function fresh(timestamp: number, now: number, maxAge: number, label: string): void {
  if (!Number.isSafeInteger(now) || now < 0 || timestamp > now || now - timestamp > maxAge) {
    throw new GuardError('SOURCE_STALE', `${label} is stale or has a future timestamp`, 503);
  }
}

/** Pure authorization rules. Inputs come from trusted injected adapters, never request-supplied claims. */
export function scoreAssessment(input: ScoringInput): ScoreResult {
  const action = actionSchema.parse(input.action);
  const policy = policySnapshotSchema.parse(input.policy);
  const evidence = receiverEvidenceSchema.parse(input.evidence);
  const reputation = reputationSnapshotSchema.parse(input.reputation);
  const { now, history } = input;
  if (!Number.isSafeInteger(history.finalized_successes) || history.finalized_successes < 0) {
    throw new GuardError('EVIDENCE_UNAVAILABLE', 'Invalid reconciled history', 503);
  }
  if (evidence.network !== policy.network || reputation.network !== policy.network
      || evidence.account_id !== action.receiver_id || reputation.account_id !== action.receiver_id) {
    throw new GuardError('EVIDENCE_UNAVAILABLE', 'Evidence network or receiver does not match the action', 503);
  }
  if (!reputation.available) throw new GuardError('SOURCE_UNAVAILABLE', 'Reviewed reputation state is unavailable', 503);
  fresh(policy.observed_at, now, policy.max_source_age_ms, 'Policy');
  fresh(reputation.observed_at, now, policy.max_source_age_ms, 'Reputation');
  if (policy.paused) throw new GuardError('POLICY_REJECTED', 'Vault policy is paused', 403);
  const amount = BigInt(action.kind === 'transfer_near' ? action.amount_yocto : action.attached_deposit_yocto);
  if (amount > BigInt(policy.max_action_yocto)) throw new GuardError('POLICY_REJECTED', 'Action exceeds the configured value limit', 403);
  if (action.kind === 'contract_call') {
    const call = policy.supported_call;
    if (!call || action.receiver_id !== call.receiver_id || action.method_name !== call.method_name
        || action.gas_tgas > call.max_gas_tgas || amount > BigInt(call.max_deposit_yocto)) {
      throw new GuardError('UNSUPPORTED_ACTION', 'Contract target, method, gas or deposit is not supported', 403);
    }
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(action.args_base64, 'base64'));
      // memo-v1 has exactly one literal key. Reject duplicate/escaped keys that parsers could interpret differently.
      const memoObject = /^\s*\{\s*"memo"\s*:\s*"(?:\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})|[^"\\\u0000-\u001f])*"\s*\}\s*$/;
      if (!memoObject.test(text)) throw new Error('Invalid memo object');
      memoArgumentsSchema.parse(JSON.parse(text));
    } catch {
      throw new GuardError('UNSUPPORTED_ACTION', 'Call arguments do not match the configured memo-v1 schema', 403);
    }
  }
  fresh(evidence.observed_at, now, policy.max_source_age_ms, 'Receiver state');
  if (!evidence.exists) throw new GuardError('POLICY_REJECTED', 'Receiver account does not exist', 403);
  const mandatoryKinds = action.kind === 'contract_call' ? ['account_state', 'contract_code'] : ['account_state'];
  for (const kind of mandatoryKinds) {
    const observations = evidence.observations.filter(observation => observation.kind === kind);
    if (observations.length !== 1) throw new GuardError('SOURCE_UNAVAILABLE', `Exactly one ${kind} observation is required`, 503);
    const observation = observations[0]!;
    if (observation.network !== evidence.network || observation.source_mode !== evidence.source_mode
      || !observation.block_hash || observation.block_height === null || observation.source_timestamp === null) {
      throw new GuardError('EVIDENCE_UNAVAILABLE', `${kind} provenance is incomplete`, 503);
    }
    fresh(observation.fetched_at, now, policy.max_source_age_ms, `${kind} fetch`);
    fresh(observation.source_timestamp, now, policy.max_source_age_ms, `${kind} underlying block`);
  }
  const anchored = evidence.observations.filter(item => mandatoryKinds.includes(item.kind));
  if (anchored.some(item => item.block_hash !== anchored[0]!.block_hash || item.block_height !== anchored[0]!.block_height)) {
    throw new GuardError('EVIDENCE_UNAVAILABLE', 'Mandatory current-state facts must use the same concrete block', 503);
  }
  if (evidence.observations.some(item => item.network !== evidence.network || item.source_mode !== evidence.source_mode)) {
    throw new GuardError('EVIDENCE_UNAVAILABLE', 'Mixed source/network observations are invalid', 503);
  }
  if (action.kind === 'contract_call' && evidence.code_identity === null) {
    throw new GuardError('SOURCE_UNAVAILABLE', 'Supported contract code identity is unavailable', 503);
  }
  const active = reputation.active_blocks.find(entry => entry.network === policy.network
    && entry.account_id === action.receiver_id && entry.expires_at > now
    && (entry.code_identity === null || entry.code_identity === evidence.code_identity));
  if (active) {
    return scoreResultSchema.parse({ decision: 'block', risk_indicator: 100,
      reason_codes: ['REVIEWED_BLOCKLIST_MATCH'], reasons: ['An authenticated reviewed active blocklist entry matches this receiver.'],
      contributions: [{ code: 'REVIEWED_BLOCKLIST_MATCH', points: 100,
        explanation: `Reviewed entry ${active.id} matches this exact network and scope.`, evidence_refs: active.evidence_refs }] });
  }
  const refs = evidence.observations.map(item => item.id);
  const contributions: ScoreResult['contributions'] = [];
  const add = (code: ReasonCode, points: number, explanation: string, evidenceRefs = refs) => {
    contributions.push({code, points, explanation, evidence_refs: evidenceRefs});
  };
  add('BASELINE_UNCERTAINTY', 40, 'Prototype baseline uncertainty; this is not a fraud probability.');
  const manipulation = Math.max(evidence.activity_manipulation_score, reputation.manipulation_score);
  const supportedActivityCredit = reputation.independent_activity_credit
    ?? (evidence.source_mode === 'fixture' ? Math.min(15, evidence.independent_successful_counterparties) : 0);
  const independentCredit = manipulation === 0 ? supportedActivityCredit : 0;
  if (independentCredit) add('INDEPENDENT_ACTIVITY', -independentCredit, 'Bounded credit for independent successful counterparties.');
  const historyCredit = Math.min(10, history.finalized_successes * 2);
  if (historyCredit) add('FINALIZED_AGENT_HISTORY', -historyCredit, 'Only this authenticated agent’s reconciled finalized successes receive credit.');
  if (evidence.account_age_days === null) add('UNKNOWN_AGE', 15, 'Account creation age is unknown; earliest observed activity is not creation proof.');
  else if (evidence.account_age_days < 7) add('NEW_ACCOUNT', 15, 'Account age is below the seven-day prototype threshold.');
  else if (evidence.transfer_count < 3) add('SPARSE_ACTIVITY', 15, 'Observed successful activity is sparse.');
  if (evidence.recent_deployment) add('RECENT_DEPLOYMENT', 20, 'A recent contract deployment was observed.');
  if (manipulation) add('CIRCULAR_ACTIVITY', manipulation, 'Activity confidence is reduced by combined dependence/circularity features; overlapping features share one cap.');
  if (reputation.unresolved_report_weight) add('UNRESOLVED_REPORT', reputation.unresolved_report_weight, 'Evidence-backed unresolved reports contribute bounded uncertainty; report count cannot create a hard block.');
  if (reputation.dependent_report_groups) add('DEPENDENT_REPORTS', 0, 'Dependent report groups were discounted; original reports remain retained.');
  if (!evidence.coverage.complete || evidence.coverage.truncated || !reputation.coverage.complete || reputation.coverage.truncated) {
    add('INCOMPLETE_HISTORY', 0, 'Bounded or incomplete historical coverage is shown explicitly and supplies no fabricated history.');
  }
  const hasApprovedIdentity = history.finalized_successes > 0 || history.approved_code_identity !== null;
  const codeChanged = history.code_identity_ambiguous === true
    || (hasApprovedIdentity && history.approved_code_identity !== evidence.code_identity);
  if (codeChanged) add('CODE_CHANGED', 0, history.code_identity_ambiguous
    ? 'Latest finalized successes have conflicting code identities without a verified within-block order; an owner warning is required.'
    : 'Current code differs from the agent’s previously approved code; reassessment and an owner warning are required.');
  const risk = Math.max(0, Math.min(100, contributions.reduce((total, item) => total + item.points, 0)));
  return scoreResultSchema.parse({decision: codeChanged || risk >= 30 ? 'warn' : 'allow', risk_indicator: risk,
    reason_codes: contributions.map(item => item.code), reasons: contributions.map(item => item.explanation), contributions});
}
