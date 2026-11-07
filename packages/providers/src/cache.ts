import type { AssessInput, ReceiverEvidence, ReceiverProvider, SourceMode } from './types.js';
import { boundedInt, type Clock } from './http.js';

/** In-memory bounded evidence cache. refresh=true always crosses the provider boundary. */
export class CachedReceiverProvider implements ReceiverProvider {
  readonly sourceMode: SourceMode;
  private readonly values = new Map<string, { cachedAt: number; value: ReceiverEvidence }>();
  constructor(private readonly inner: ReceiverProvider, private readonly options: { ttlMs?: number; maxEntries?: number; clock?: Clock } = {}) {
    this.sourceMode = inner.sourceMode;
    boundedInt(options.ttlMs ?? 5_000, 0, 60_000, 'ttlMs');
    boundedInt(options.maxEntries ?? 128, 1, 1_000, 'maxEntries');
  }
  invalidate(network?: string, accountId?: string): void {
    if (!network) { this.values.clear(); return; }
    for (const [key, entry] of this.values) if (entry.value.network === network && (!accountId || entry.value.account_id === accountId)) this.values.delete(key);
  }
  async assess(input: AssessInput): Promise<ReceiverEvidence> {
    const now = (this.options.clock ?? Date.now)();
    const key = JSON.stringify([this.sourceMode, input.network, input.account_id, input.action]);
    const entry = this.values.get(key);
    const age = entry ? now - entry.cachedAt : Infinity;
    if (!input.refresh && entry && age >= 0 && age < (this.options.ttlMs ?? 5_000)) {
      this.values.delete(key);
      this.values.set(key, entry);
      return structuredClone(entry.value);
    }
    // Once a fresh lookup is required, a failure must not expose the prior clean result.
    this.values.delete(key);
    const value = await this.inner.assess(input);
    this.values.set(key, { cachedAt: now, value: structuredClone(value) });
    while (this.values.size > (this.options.maxEntries ?? 128)) this.values.delete(this.values.keys().next().value!);
    return structuredClone(value);
  }
}
