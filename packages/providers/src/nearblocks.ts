import { createHash } from 'node:crypto';
import { accountIdSchema, amountSchema, canonicalJson } from '@counterparty-guard/shared';
import { JsonTransport, ProviderError, boundedInt, fixedBaseUrl, object, textField, unsigned, type Clock, type HttpOptions } from './http.js';
import { coverage, type IndexedHistory, type Network, type SourceObservation, type TransferEdge } from './types.js';

const DAY_MS = 86_400_000;
export interface NearBlocksOptions extends HttpOptions {
  baseUrl?: string;
  apiKey?: string;
  maxPages?: number;
  pageSize?: number;
  maxNodes?: number;
  maxEdges?: number;
  maxHops?: number;
  maxDurationMs?: number;
}

/** NearBlocks v3, verified against the official OpenAPI and migration reference. */
export class NearBlocksClient {
  private readonly base: URL;
  private readonly transport: JsonTransport;
  private readonly clock: Clock;
  private readonly headers: Record<string, string>;
  private readonly maxPages: number;
  private readonly pageSize: number;
  private readonly maxNodes: number;
  private readonly maxEdges: number;
  private readonly maxHops: number;
  private readonly maxDurationMs: number;
  constructor(options: NearBlocksOptions = {}) {
    this.base = fixedBaseUrl(options.baseUrl ?? 'https://api-testnet.nearblocks.io');
    this.transport = new JsonTransport(options);
    this.clock = options.clock ?? Date.now;
    if (options.apiKey && /[\r\n]/.test(options.apiKey)) throw new TypeError('Invalid API credential');
    this.headers = options.apiKey ? { authorization: `Bearer ${options.apiKey}` } : {};
    this.maxPages = boundedInt(options.maxPages ?? 8, 1, 16, 'maxPages');
    this.pageSize = boundedInt(options.pageSize ?? 25, 1, 100, 'pageSize');
    this.maxNodes = boundedInt(options.maxNodes ?? 100, 1, 100, 'maxNodes');
    this.maxEdges = boundedInt(options.maxEdges ?? 500, 1, 500, 'maxEdges');
    this.maxDurationMs = boundedInt(options.maxDurationMs ?? 15_000, 1, 20_000, 'maxDurationMs');
    this.maxHops = boundedInt(options.maxHops ?? 2, 1, 2, 'maxHops');
  }
  private url(accountId: string, suffix = ''): URL {
    accountIdSchema.parse(accountId);
    return new URL(`/v3/accounts/${encodeURIComponent(accountId)}${suffix}`, this.base);
  }
  private async get(url: URL, signal?: AbortSignal): Promise<Record<string, unknown>> {
    const result = object(await this.transport.request(url, { headers: this.headers, signal }), 'NearBlocks response', this.base.origin);
    if (result.data === null || result.errors !== undefined) throw new ProviderError('SOURCE_UNAVAILABLE', 'NearBlocks reported unavailable data', this.base.origin);
    if (!('data' in result)) throw new ProviderError('SOURCE_MALFORMED', 'NearBlocks v3 data envelope is missing', this.base.origin);
    return result;
  }
  private observation(kind: string, raw: Record<string, unknown>, now: number, pages: number, sourceTimestamp: number | null = null): SourceObservation {
    const hash = createHash('sha256').update(canonicalJson(raw)).digest('hex');
    const data = Array.isArray(raw.data) ? raw.data[0] : raw.data;
    const record = data && typeof data === 'object' ? data as Record<string, unknown> : {};
    const block = record.block && typeof record.block === 'object' ? record.block as Record<string, unknown> : {};
    const blockHeight = block.block_height === undefined ? null : unsigned(block.block_height, 'block_height', this.base.origin);
    const blockHash = block.block_hash === undefined ? null : textField(block.block_hash, 'block_hash', this.base.origin, 128);
    return { id: `nearblocks-${kind}-${hash.slice(0, 16)}`, kind, network: 'testnet', source_mode: 'live-testnet', source: this.base.origin, fetched_at: this.clock(), source_timestamp: sourceTimestamp, block_height: blockHeight, block_hash: blockHash, coverage: { complete: false, truncated: false, pages, window_start_ms: now - 7 * DAY_MS, window_end_ms: now, notes: ['Indexed history is contextual; it is not finalized execution proof.'] }, raw_hash: hash, value: raw };
  }
  async collect(network: Network, accountId: string): Promise<IndexedHistory> {
    if (network !== 'testnet') throw new ProviderError('NETWORK_MISMATCH', 'NearBlocks adapter is testnet-only', this.base.origin);
    accountIdSchema.parse(accountId);
    const deadline = new AbortController();
    const deadlineTimer = setTimeout(() => deadline.abort(), this.maxDurationMs);
    try {
    const now = this.clock();
    const result: IndexedHistory = { account_age_days: null, recent_deployment: false, edges: [], observations: [], coverage: coverage(now) };
    const notes = result.coverage.notes;
    try {
      const raw = await this.get(this.url(accountId), deadline.signal);
      const details = object(raw.data, 'account data', this.base.origin);
      if (details.account_id !== accountId) throw new ProviderError('SOURCE_MALFORMED', 'Indexer returned another account', this.base.origin);
      const created = object(details.created, 'created metadata', this.base.origin);
      const deleted = object(details.deleted, 'deleted metadata', this.base.origin);
      // A deleted/recreated lifecycle is ambiguous without complete creation history.
      const createdAt = optionalTimestamp(created, this.base.origin);
      if (Object.keys(deleted).length === 0 && createdAt !== null && createdAt <= now) result.account_age_days = (now - createdAt) / DAY_MS;
      else notes.push('Account age is unknown; creation metadata or lifecycle coverage is incomplete.');
      result.observations.push(this.observation('account_history', raw, now, 1, createdAt));
    } catch (error) { notes.push(optionalFailure('Account creation history', error)); }
    try {
      const raw = await this.get(this.url(accountId, '/contract/deployments'), deadline.signal);
      if (!Array.isArray(raw.data) || raw.data.length > 500) throw new ProviderError('SOURCE_MALFORMED', 'Deployment data must be a bounded list', this.base.origin);
      const times = raw.data.map((row) => optionalTimestamp(object(row, 'deployment', this.base.origin), this.base.origin)).filter((time): time is number => time !== null && time <= now);
      const latest = times.length ? Math.max(...times) : null;
      result.recent_deployment = latest !== null && now - latest <= DAY_MS;
      result.observations.push(this.observation('deployments', raw, now, 1, latest));
      if (latest === null) notes.push('No verified deployment time is available from this indexed window.');
    } catch (error) { notes.push(optionalFailure('Deployment history', error)); }

    const visited = new Set<string>();
    const nodes = new Set([accountId]);
    const seenReceipts = new Set<string>();
    const queue: { account: string; depth: number }[] = [{ account: accountId, depth: 0 }];
    let allPagesComplete = true;
    while (queue.length && result.coverage.pages < this.maxPages && !deadline.signal.aborted) {
      const item = queue.shift()!;
      if (visited.has(item.account)) continue;
      visited.add(item.account);
      let cursor: string | undefined;
      const seenCursors = new Set<string>();
      do {
        const url = this.url(item.account, '/receipts');
        url.searchParams.set('limit', String(this.pageSize));
        // The cursor is an opaque token. Never interpret or construct its contents.
        if (cursor) url.searchParams.set('next', cursor);
        try {
          const raw = await this.get(url, deadline.signal);
          result.coverage.pages++;
          if (!Array.isArray(raw.data) || raw.data.length > this.pageSize) throw new ProviderError('SOURCE_MALFORMED', 'Receipt page has an invalid size', this.base.origin);
          const observation = this.observation('receipts', raw, now, 1);
          result.observations.push(observation);
          let oldest: number | null = null;
          const pending: unknown[] = [...raw.data];
          let walked = 0;
          while (pending.length) {
            if (++walked > 1_000) { notes.push('Nested receipt processing limit reached.'); result.coverage.truncated = true; break; }
            const row = object(pending.shift(), 'receipt', this.base.origin);
            if (row.receipts !== undefined) {
              if (!Array.isArray(row.receipts)) throw new ProviderError('SOURCE_MALFORMED', 'Nested receipts must be a list', this.base.origin);
              pending.push(...row.receipts);
            }
            const timestamp = optionalTimestamp(row, this.base.origin);
            if (timestamp === null) throw new ProviderError('SOURCE_MALFORMED', 'Receipt lacks a block timestamp', this.base.origin);
            oldest = oldest === null ? timestamp : Math.min(oldest, timestamp);
            if (timestamp < now - 7 * DAY_MS) { result.coverage.truncated = true; notes.push('History restricted to the seven-day window.'); continue; }
            if (timestamp > now) throw new ProviderError('SOURCE_MALFORMED', 'Indexed receipt timestamp is in the future', this.base.origin);
            const edge = parseTransfer(row, timestamp, this.base.origin);
            if (!edge || (edge.predecessor_id !== item.account && edge.receiver_id !== item.account) || seenReceipts.has(edge.receipt_id)) continue;
            seenReceipts.add(edge.receipt_id);
            const newNodes = [edge.predecessor_id, edge.receiver_id].filter((id) => !nodes.has(id));
            if (nodes.size + new Set(newNodes).size > this.maxNodes) { notes.push('Graph node limit reached.'); result.coverage.truncated = true; continue; }
            if (result.edges.length >= this.maxEdges) { notes.push('Graph edge limit reached.'); result.coverage.truncated = true; continue; }
            newNodes.forEach((id) => nodes.add(id));
            result.edges.push(edge);
            if (item.depth >= this.maxHops - 1 && [edge.predecessor_id, edge.receiver_id].some((id) => !visited.has(id))) { result.coverage.truncated = true; notes.push('Graph relationship-depth limit reached.'); }
            if (item.depth < this.maxHops - 1) for (const id of [edge.predecessor_id, edge.receiver_id]) if (!visited.has(id)) queue.push({ account: id, depth: item.depth + 1 });
          }
          observation.source_timestamp = raw.data[0] ? optionalTimestamp(object(raw.data[0], 'receipt', this.base.origin), this.base.origin) : null;
          const firstBlock = raw.data[0] && typeof raw.data[0] === 'object' ? (raw.data[0] as Record<string, unknown>).block : undefined;
          if (firstBlock && typeof firstBlock === 'object') {
            const ref = firstBlock as Record<string, unknown>;
            observation.block_height = unsigned(ref.block_height, 'block_height', this.base.origin);
            observation.block_hash = textField(ref.block_hash, 'block_hash', this.base.origin, 128);
          }
          const meta = raw.meta === undefined ? {} : object(raw.meta, 'pagination metadata', this.base.origin);
          cursor = meta.next_page === undefined || meta.next_page === null ? undefined : textField(meta.next_page, 'next_page cursor', this.base.origin, 4096);
          if (cursor && seenCursors.has(cursor)) { result.coverage.truncated = true; throw new ProviderError('SOURCE_MALFORMED', 'Indexer repeated a pagination cursor', this.base.origin); }
          if (cursor) seenCursors.add(cursor);
          if (oldest !== null && oldest < now - 7 * DAY_MS) cursor = undefined;
          if (cursor && result.coverage.pages >= this.maxPages) { result.coverage.truncated = true; allPagesComplete = false; notes.push('Receipt pagination limit reached.'); }
        } catch (error) {
          allPagesComplete = false;
          notes.push(optionalFailure('Receipt history', error));
          cursor = undefined;
        }
      } while (cursor && result.coverage.pages < this.maxPages && !deadline.signal.aborted);
    }
    if (deadline.signal.aborted) { result.coverage.truncated = true; notes.push('History collection deadline reached; remaining context is unknown.'); }
    if (queue.length) { result.coverage.truncated = true; notes.push('Graph request budget reached before every discovered account was visited.'); }
    result.coverage.complete = allPagesComplete && !result.coverage.truncated && notes.length === 0;
    result.coverage.notes = [...new Set(notes)].slice(0, 32);
    const graph = { edges: result.edges, visited_accounts: [...visited].sort(), bounds: { max_hops: this.maxHops, max_nodes: this.maxNodes, max_edges: this.maxEdges, max_pages: this.maxPages, max_duration_ms: this.maxDurationMs, window_days: 7 }, source_observation_ids: result.observations.map((entry) => entry.id) };
    const graphHash = createHash('sha256').update(canonicalJson(graph)).digest('hex');
    const newest = [...result.edges].sort((a, b) => b.timestamp_ms - a.timestamp_ms)[0];
    result.observations.push({ id: `transfer-graph-${graphHash.slice(0, 24)}`, kind: 'transfer_graph', network: 'testnet', source_mode: 'live-testnet', source: this.base.origin, fetched_at: this.clock(), source_timestamp: newest?.timestamp_ms ?? null, block_height: newest?.block_height ?? null, block_hash: newest?.block_hash ?? null, coverage: structuredClone(result.coverage), raw_hash: graphHash, value: graph });
    // Limit explanations even if every bounded optional request failed.
    result.coverage.notes = [...new Set(notes)].slice(0, 32);
    return result;
    } finally { clearTimeout(deadlineTimer); }
  }
}

function optionalTimestamp(row: Record<string, unknown>, source: string): number | null {
  const block = row.block === undefined ? null : object(row.block, 'block metadata', source);
  const value = block?.block_timestamp ?? row.block_timestamp ?? row.included_in_block_timestamp;
  if (value === undefined || value === null) return null;
  const nanos = BigInt(unsigned(value, 'timestamp nanoseconds', source));
  const millis = Number(nanos / 1_000_000n);
  if (!Number.isSafeInteger(millis)) throw new ProviderError('SOURCE_MALFORMED', 'Timestamp exceeds supported range', source);
  return millis;
}
function parseTransfer(row: Record<string, unknown>, timestamp: number, source: string): TransferEdge | null {
  const outcome = object(row.outcome, 'receipt outcome', source);
  if (outcome.status !== true) return null;
  if (!Array.isArray(row.actions) || row.actions.length === 0 || row.actions.some((action) => object(action, 'action', source).action !== 'TRANSFER')) return null;
  const aggregate = object(row.actions_agg, 'receipt action aggregate', source);
  const amount = unsigned(aggregate.deposit, 'deposit', source);
  if (!amountSchema.safeParse(amount).success) throw new ProviderError('SOURCE_MALFORMED', 'Transfer deposit exceeds u128', source);
  if (BigInt(amount) === 0n) return null;
  const predecessor = accountIdSchema.safeParse(row.predecessor_account_id);
  const receiver = accountIdSchema.safeParse(row.receiver_account_id);
  if (!predecessor.success || !receiver.success) throw new ProviderError('SOURCE_MALFORMED', 'Invalid receipt account identity', source);
  const block = object(row.block, 'receipt block', source);
  return { receipt_id: textField(row.receipt_id, 'receipt_id', source, 128), transaction_hash: textField(row.transaction_hash, 'transaction_hash', source, 128), predecessor_id: predecessor.data, receiver_id: receiver.data, amount_yocto: amount, timestamp_ms: timestamp, block_height: unsigned(block.block_height, 'block_height', source), block_hash: textField(block.block_hash, 'block_hash', source, 128) };
}
function optionalFailure(label: string, error: unknown): string {
  return `${label} unavailable (${error instanceof ProviderError ? error.code : 'SOURCE_MALFORMED'}); no trust credit awarded.`;
}
