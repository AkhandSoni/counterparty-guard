/** Actual A+C assessment over visibly synthetic inputs; never signs/submits a chain transaction. */
import { generateKeyPairSync } from 'node:crypto';
import { publicKeyFromKeyObject, signPermit, type Action, type ReceiverEvidence } from '@counterparty-guard/shared';
import { createReputationProvider, type BoundedSubgraph, type ReportRepository } from '@counterparty-guard/reputation';
import { AssessmentService } from '../../../apps/api/src/services/assess.js';
import { GuardStore, credentialHash, digest } from '../../../apps/api/src/storage/store.js';

export async function assessFixtureAction(action: Action, repository: ReportRepository, options: {
  reportNetwork?: 'testnet' | 'sandbox'; now?: number; ageDays?: number | null; independentCounterparties?: number; currentCode?: string | null;
  previousCode?: string | null; graph?: BoundedSubgraph; unavailable?: boolean;
} = {}) {
  const now = options.now ?? Date.now();
  const store = new GuardStore();
  const scorer = generateKeyPairSync('ed25519');
  const agentKey = generateKeyPairSync('ed25519');
  const agent = { agent_id: 'fixture-agent', account_id: 'fixture-agent.testnet', public_key: publicKeyFromKeyObject(agentKey.publicKey), credential_hash: credentialHash('fixture-unused-credential'), network: 'sandbox' as const, vault_id: 'fixture-vault.testnet' };
  store.registerAgent(agent, now);
  // A declared fixture approval baseline, not a claimed finalized payment or history credit.
  if (options.previousCode !== undefined) store.history = () => ({ finalized_successes: 0, approved_code_identity: options.previousCode ?? null });
  const coverage = { complete: true, truncated: false, pages: 1, window_start_ms: null, window_end_ms: null, notes: ['Synthetic fixture evidence; no chain execution.'] };
  const observation = (kind: string, value: unknown) => ({ id: `fixture:${kind}`, kind, network: 'sandbox' as const, source_mode: 'fixture' as const, source: 'declared-demo-fixture', fetched_at: now, source_timestamp: now, block_height: '1', block_hash: 'fixture-block', coverage, raw_hash: digest(value), value });
  const edges = (options.graph?.edges ?? []).map(edge => ({ receipt_id: `fixture:${edge.id}`, predecessor_id: edge.source, receiver_id: edge.target, amount_yocto: edge.amountYocto ?? '1', timestamp_ms: edge.timestamp }));
  const evidence: ReceiverEvidence = { network: 'sandbox', source_mode: 'fixture', account_id: action.receiver_id, exists: true,
    code_identity: options.currentCode ?? null, account_age_days: options.ageDays ?? null, recent_deployment: false,
    independent_successful_counterparties: options.independentCounterparties ?? 0, transfer_count: Math.max(edges.length, options.independentCounterparties ?? 0), activity_manipulation_score: 0,
    observations: [observation('account_state', { fixture: true, account_id: action.receiver_id }),
      ...(action.kind === 'contract_call' ? [observation('contract_code', { fixture: true, code: options.currentCode ?? null })] : []),
      observation('transfer_graph', { edges })], coverage, observed_at: now };
  const reputation = createReputationProvider(repository, () => now);
  const service = new AssessmentService({ store, sourceMode: 'fixture', scorerPublicKey: publicKeyFromKeyObject(scorer.publicKey), clock: () => now,
    signPermit: payload => signPermit(payload, scorer.privateKey),
    receiverProvider: { sourceMode: 'fixture', async assess() { if (options.unavailable) throw new Error('Fixture mandatory-source outage'); return evidence; } },
    policyProvider: { async getPolicy() { return { network: 'sandbox', vault_id: agent.vault_id, deployment_instance_id: '11'.repeat(32), revision: '1', observed_at: now, paused: false, max_action_yocto: '10000000000000000000000000', permit_ttl_ms: 120000, max_source_age_ms: 60000,
      supported_call: action.kind === 'contract_call' ? { receiver_id: action.receiver_id, method_name: 'accept_memo', max_gas_tgas: 50, max_deposit_yocto: '100000000000000000000000', argument_schema: 'memo-v1' } : null }; } },
    reputationProvider: { async getReputation(_network, accountId, currentEvidence) {
      // Demo repositories historically used testnet fixture names; map explicitly to sandbox scope.
      const sourceNetwork = options.reportNetwork ?? 'sandbox';
      const result = await reputation.getReputation(sourceNetwork, accountId, { ...currentEvidence, network: sourceNetwork });
      return { ...result, network: 'sandbox', active_blocks: result.active_blocks.map(block => ({ ...block, network: 'sandbox' })) };
    } },
  });
  try { return await service.assess(agent, { schema_version: 1, network: 'sandbox', vault_id: agent.vault_id, request_id: 'fixture-assessment', action }); }
  finally { store.close(); }
}
