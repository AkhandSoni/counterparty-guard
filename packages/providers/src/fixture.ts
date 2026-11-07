import { receiverEvidenceSchema } from '@counterparty-guard/shared';
import { ProviderError } from './http.js';
import type { AssessInput, ReceiverEvidence, ReceiverProvider } from './types.js';

/** Explicit fixture records retain their supplied timestamps, including stale ones. */
export class FixtureProvider implements ReceiverProvider {
  readonly sourceMode = 'fixture' as const;
  private readonly records = new Map<string, ReceiverEvidence>();
  constructor(records: readonly ReceiverEvidence[] = []) { records.forEach((record) => this.set(record)); }
  set(record: ReceiverEvidence): void {
    const parsed = receiverEvidenceSchema.parse(record);
    if (parsed.source_mode !== 'fixture' || parsed.observations.some((observation) => observation.source_mode !== 'fixture' || observation.network !== parsed.network)) throw new TypeError('Fixture evidence must be consistently labelled and network-scoped');
    this.records.set(`${parsed.network}:${parsed.account_id}`, structuredClone(parsed));
  }
  async assess(input: AssessInput): Promise<ReceiverEvidence> {
    const record = this.records.get(`${input.network}:${input.account_id}`);
    if (!record) throw new ProviderError('SOURCE_UNAVAILABLE', 'No labelled fixture exists for this network/account', 'fixture');
    if (input.action.receiver_id !== input.account_id) throw new ProviderError('SOURCE_MALFORMED', 'Action receiver and requested account differ', 'fixture');
    return structuredClone(record);
  }
}
