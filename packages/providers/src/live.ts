import { receiverEvidenceSchema } from '@counterparty-guard/shared';
import { ProviderError, type Clock } from './http.js';
import { NearRpcClient } from './rpc.js';
import { NearBlocksClient } from './nearblocks.js';
import { coverage, type AssessInput, type ReceiverEvidence, type ReceiverProvider } from './types.js';

export interface LiveProviderOptions { rpc: NearRpcClient; indexer?: NearBlocksClient; clock?: Clock }
/** Required RPC failures propagate; missing contextual history is explicit, never invented. */
export class LiveReceiverProvider implements ReceiverProvider {
  readonly sourceMode = 'live-testnet' as const;
  constructor(private readonly options: LiveProviderOptions) {
    if (options.rpc.network !== 'testnet') throw new TypeError('LiveReceiverProvider only supports testnet');
  }
  async assess(input: AssessInput): Promise<ReceiverEvidence> {
    if (input.network !== 'testnet') throw new ProviderError('NETWORK_MISMATCH', 'Live provider is testnet-only', 'rpc');
    if (input.action.receiver_id !== input.account_id) throw new ProviderError('SOURCE_MALFORMED', 'Action receiver and requested account differ', 'rpc');
    const state = await this.options.rpc.getAccount(input.network, input.account_id);
    if (input.action.kind === 'contract_call' && state.code_identity === null) throw new ProviderError('UNSUPPORTED_CODE', 'Contract identity is absent or uses an unsupported global-code representation', 'rpc');
    const now = (this.options.clock ?? Date.now)();
    const history = this.options.indexer ? await this.options.indexer.collect(input.network, input.account_id) : { account_age_days: null, recent_deployment: false, edges: [], observations: [], coverage: coverage(now, ['Optional indexer is not configured; account age/activity/deployment history are unknown.']) };
    return receiverEvidenceSchema.parse({ network: input.network, source_mode: this.sourceMode, account_id: input.account_id, exists: state.exists, code_identity: state.code_identity, account_age_days: history.account_age_days, recent_deployment: history.recent_deployment, independent_successful_counterparties: 0, transfer_count: history.edges.filter((edge) => edge.predecessor_id === input.account_id || edge.receiver_id === input.account_id).length, activity_manipulation_score: 0, observations: [...state.observations, ...history.observations], coverage: history.coverage, observed_at: state.observed_at });
  }
}
