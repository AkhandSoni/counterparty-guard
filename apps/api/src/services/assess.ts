import {
  PERMIT_DOMAIN, checkRequestSchema, checkResponseSchema, policySnapshotSchema, receiverEvidenceSchema,
  reputationSnapshotSchema, signedPermitSchema, verifySignedPermit, type AgentRegistration, type CheckRequest, type CheckResponse,
  type ExecutionProvider, type Permit, type PolicyProvider, type ReceiverProvider, type ReputationProvider,
  type SignedPermit, type SourceMode,
} from '@counterparty-guard/shared';
import { scoreAssessment } from '@counterparty-guard/scoring';
import { ApiError } from '../errors.js';
import { canonical, digest, type EvidenceSnapshot, type GuardStore, type StoredCheck } from '../storage/store.js';

export interface AssessmentDependencies {
  store: GuardStore;
  receiverProvider: ReceiverProvider;
  policyProvider: PolicyProvider;
  reputationProvider: ReputationProvider;
  signPermit: (permit: Permit) => SignedPermit | Promise<SignedPermit>;
  sourceMode: SourceMode;
  scorerPublicKey: string;
  clock?: () => number;
  executionProvider?: ExecutionProvider;
}
function trustedData<T>(parse: () => T): T {
  try { return parse(); }
  catch { throw new ApiError('EVIDENCE_UNAVAILABLE', 'Provider evidence did not satisfy the authorization contract', 503); }
}
function authorityFacts(snapshot: Pick<EvidenceSnapshot, 'policy' | 'reputation'>): unknown {
  const reputation = snapshot.reputation;
  return {
    policy: { ...snapshot.policy, observed_at: 0 },
    reputation: {
      network: reputation.network, account_id: reputation.account_id, blocklist_revision: reputation.blocklist_revision,
      available: reputation.available, active_blocks: [...reputation.active_blocks].sort((a, b) => a.id.localeCompare(b.id)),
      unresolved_report_weight: reputation.unresolved_report_weight, dependent_report_groups: reputation.dependent_report_groups,
      manipulation_score: reputation.manipulation_score, independent_activity_credit: reputation.independent_activity_credit ?? null,
      complete: reputation.coverage.complete, truncated: reputation.coverage.truncated,
    },
  };
}
export class AssessmentService {
  private readonly now: () => number;
  constructor(readonly dependencies: AssessmentDependencies) {
    this.now = dependencies.clock ?? Date.now;
    if (dependencies.receiverProvider.sourceMode !== dependencies.sourceMode) throw new Error('Receiver provider source mode does not match configured mode');
  }
  private bind(agent: AgentRegistration, request: CheckRequest): void {
    if (agent.public_key === this.dependencies.scorerPublicKey) throw new ApiError('FORBIDDEN', 'Agent and scorer must use separate signing keys', 403);
    if (request.network !== agent.network || request.vault_id !== agent.vault_id) throw new ApiError('FORBIDDEN', 'Agent is not registered for this network and vault', 403);
    if (this.dependencies.sourceMode === 'live-testnet' && agent.network !== 'testnet') throw new ApiError('FORBIDDEN', 'Live-testnet providers require testnet registration', 403);
  }
  private async snapshot(agent: AgentRegistration, request: CheckRequest, refresh = false): Promise<EvidenceSnapshot> {
    this.bind(agent, request);
    const [rawEvidence, rawPolicy] = await Promise.all([
      this.dependencies.receiverProvider.assess({ network: request.network, account_id: request.action.receiver_id, action: structuredClone(request.action), refresh }),
      this.dependencies.policyProvider.getPolicy(structuredClone(agent)),
    ]);
    let evidence;
    let policy;
    let reputation;
    try {
      evidence = structuredClone(receiverEvidenceSchema.parse(rawEvidence));
      policy = policySnapshotSchema.parse(rawPolicy);
      reputation = reputationSnapshotSchema.parse(await this.dependencies.reputationProvider.getReputation(request.network, request.action.receiver_id, structuredClone(evidence)));
    } catch {
      throw new ApiError('EVIDENCE_UNAVAILABLE', 'Provider evidence did not satisfy the authorization contract', 503);
    }
    if (evidence.observations.some(observation => observation.raw_hash !== digest(observation.value))) throw new ApiError('EVIDENCE_UNAVAILABLE', 'Retained source value does not match its provenance hash', 503);
    if (evidence.source_mode !== this.dependencies.sourceMode) throw new ApiError('SOURCE_UNAVAILABLE', 'Provider returned mismatched source mode', 503);
    if (policy.network !== agent.network || policy.vault_id !== agent.vault_id) throw new ApiError('SOURCE_UNAVAILABLE', 'Policy does not bind to the registered vault', 503);
    const history = this.dependencies.store.history(agent, request.action.receiver_id, this.dependencies.sourceMode);
    return { evidence, reputation, policy, history };
  }
  async assess(agent: AgentRegistration, rawRequest: unknown): Promise<CheckResponse> {
    const request = checkRequestSchema.parse(rawRequest);
    this.bind(agent, request);
    const claim = this.dependencies.store.claim(agent, request, this.dependencies.sourceMode, this.now());
    if (claim.cached) return claim.cached;
    try {
      const snapshot = await this.snapshot(agent, request);
      const evaluatedAt = this.now();
      let result = scoreAssessment({ action: request.action, ...snapshot, now: evaluatedAt });
      // Re-read authority revisions immediately before constructing the authorization.
      const [rawLatestPolicy, rawLatestReputation] = await Promise.all([
        this.dependencies.policyProvider.getPolicy(structuredClone(agent)),
        this.dependencies.reputationProvider.getReputation(request.network, request.action.receiver_id, structuredClone(snapshot.evidence)),
      ]);
      const latestPolicy = trustedData(() => policySnapshotSchema.parse(rawLatestPolicy));
      const latestReputation = trustedData(() => reputationSnapshotSchema.parse(rawLatestReputation));
      const policyFacts = (policy: typeof latestPolicy): unknown => ({ ...policy, observed_at: 0 });
      if (canonical(policyFacts(latestPolicy)) !== canonical(policyFacts(snapshot.policy)) || latestReputation.blocklist_revision !== snapshot.reputation.blocklist_revision || digest(latestReputation.active_blocks) !== digest(snapshot.reputation.active_blocks)) throw new ApiError('SOURCE_UNAVAILABLE', 'Authorization state changed during assessment; retry this request', 503);
      const issuedAt = this.now();
      snapshot.policy = latestPolicy;
      snapshot.reputation = latestReputation;
      result = scoreAssessment({ action: request.action, ...snapshot, now: issuedAt });
      const expiresAt = issuedAt + snapshot.policy.permit_ttl_ms;
      let permit: SignedPermit | null = null;
      if (result.decision !== 'block') {
        const payload: Permit = {
          domain: PERMIT_DOMAIN, version: 1, network: request.network,
          deployment_instance_id: snapshot.policy.deployment_instance_id, vault_id: request.vault_id,
          agent_account_id: agent.account_id, agent_public_key: agent.public_key, action: request.action,
          policy_revision: snapshot.policy.revision, blocklist_revision: snapshot.reputation.blocklist_revision,
          evidence_snapshot_hash: digest(snapshot), verdict: result.decision, nonce: claim.nonce,
          issued_at: issuedAt, expires_at: expiresAt,
        };
        const expectedPayload = canonical(payload);
        const signed = await this.dependencies.signPermit(structuredClone(payload));
        try { permit = signedPermitSchema.parse(signed); }
        catch { throw new ApiError('INTERNAL_ERROR', 'Signer returned an invalid permit envelope', 500); }
        if (!verifySignedPermit(permit, this.dependencies.scorerPublicKey) || canonical(permit.payload) !== expectedPayload) throw new ApiError('INTERNAL_ERROR', 'Signer changed the reconstructed permit', 500);
        if (this.now() >= expiresAt) throw new ApiError('SOURCE_STALE', 'Permit expired before durable issuance', 503);
        // Asynchronous signers can cross a policy/review change; re-read known authority before commit.
        const [finalPolicyRaw, finalReputationRaw] = await Promise.all([
          this.dependencies.policyProvider.getPolicy(structuredClone(agent)),
          this.dependencies.reputationProvider.getReputation(request.network, request.action.receiver_id, structuredClone(snapshot.evidence)),
        ]);
        const finalAuthority = trustedData(() => ({ policy: policySnapshotSchema.parse(finalPolicyRaw), reputation: reputationSnapshotSchema.parse(finalReputationRaw) }));
        if (digest(authorityFacts(finalAuthority)) !== digest(authorityFacts(snapshot))) throw new ApiError('SOURCE_UNAVAILABLE', 'Authorization state changed while signing; retry the same request', 503);
        scoreAssessment({ action: request.action, ...snapshot, ...finalAuthority, now: this.now() });
        if (this.now() >= expiresAt) throw new ApiError('SOURCE_STALE', 'Permit expired before durable issuance', 503);
      }
      const response = checkResponseSchema.parse({
        schema_version: 1, check_id: claim.id, agent_id: agent.agent_id, ...result,
        evidence_refs: snapshot.evidence.observations.map(observation => observation.id),
        coverage: snapshot.evidence.coverage, source_mode: this.dependencies.sourceMode,
        evaluated_at: evaluatedAt, expires_at: expiresAt, policy_revision: snapshot.policy.revision,
        blocklist_revision: snapshot.reputation.blocklist_revision, permit, attestation: null,
      });
      this.dependencies.store.complete(claim, agent, request, snapshot, response);
      return response;
    } catch (error) {
      this.dependencies.store.release(claim);
      throw error;
    }
  }
  check(agent: AgentRegistration, id: string): StoredCheck {
    const result = this.dependencies.store.check(id, agent.agent_id);
    if (!result) throw new ApiError('NOT_FOUND', 'Assessment was not found', 404);
    return result;
  }
  async revalidate(agent: AgentRegistration, id: string): Promise<{ check_id: string; status: 'valid' | 'expired' | 'invalidated' | 'in_flight' | 'consumed'; reason: string | null; expires_at: number }> {
    const stored = this.check(agent, id);
    const base = { check_id: id, expires_at: stored.response.expires_at };
    if (stored.response.expires_at <= this.now()) return { ...base, status: 'expired', reason: 'Original permit expiry has elapsed' };
    if (stored.row.invalidated_reason) return { ...base, status: 'invalidated', reason: stored.row.invalidated_reason };
    const execution = this.dependencies.store.execution(id, agent.agent_id);
    if (execution?.finalized) return { ...base, status: 'consumed', reason: 'This permit already has a finalized execution outcome' };
    if (execution?.signed || execution?.submitted) return { ...base, status: 'in_flight', reason: 'Transaction signing or submission is already recorded; reconcile the existing execution' };
    const request: CheckRequest = { schema_version: 1, request_id: stored.row.request_id, network: stored.row.network, vault_id: stored.row.vault_id, action: JSON.parse(stored.row.action_json) as CheckRequest['action'] };
    const snapshot = await this.snapshot(agent, request, true);
    const result = scoreAssessment({ action: request.action, ...snapshot, now: this.now() });
    const securityFacts = (value: EvidenceSnapshot): unknown => ({
      authority: authorityFacts(value),
      evidence: {
        exists: value.evidence.exists, code_identity: value.evidence.code_identity,
        age_band: value.evidence.account_age_days === null ? 'unknown' : value.evidence.account_age_days < 7 ? 'new' : 'established',
        recent_deployment: value.evidence.recent_deployment,
        independent_successful_counterparties: value.evidence.independent_successful_counterparties,
        transfer_count: value.evidence.transfer_count,
        activity_manipulation_score: value.evidence.activity_manipulation_score,
        complete: value.evidence.coverage.complete, truncated: value.evidence.coverage.truncated,
      },
    });
    const changed = digest(securityFacts(snapshot)) !== digest(securityFacts(stored.snapshot)) ||
      result.decision === 'block' || (stored.response.decision === 'allow' && result.decision !== 'allow');
    if (changed || stored.response.decision === 'block') {
      const reason = 'Security facts or authorization revision changed; obtain a new assessment';
      this.dependencies.store.invalidate(id, reason);
      return { ...base, status: 'invalidated', reason };
    }
    if (stored.response.expires_at <= this.now()) return { ...base, status: 'expired', reason: 'Original permit expiry has elapsed' };
    // Local invalidation or execution may have committed while sources were being awaited.
    const latest = this.check(agent, id);
    if (latest.row.invalidated_reason) return { ...base, status: 'invalidated', reason: latest.row.invalidated_reason };
    const currentExecution = this.dependencies.store.execution(id, agent.agent_id);
    if (currentExecution?.finalized) return { ...base, status: 'consumed', reason: 'This permit already has a finalized execution outcome' };
    if (currentExecution?.signed || currentExecution?.submitted) return { ...base, status: 'in_flight', reason: 'Transaction signing or submission is already recorded; reconcile the existing execution' };
    return { ...base, status: 'valid', reason: null };
  }
  async execution(agent: AgentRegistration, id: string): Promise<ReturnType<GuardStore['execution']>> {
    const prior = this.dependencies.store.execution(id, agent.agent_id);
    if (!prior) throw new ApiError('NOT_FOUND', 'Execution was not found', 404);
    if (this.dependencies.executionProvider) {
      const evidence = await this.dependencies.executionProvider.getExecution(prior.network, prior.vault_id, prior.id);
      this.dependencies.store.reconcile(evidence);
    }
    return this.dependencies.store.execution(id, agent.agent_id);
  }
}
