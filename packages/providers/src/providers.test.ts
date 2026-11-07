import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalJson, type ReceiverEvidence } from '@counterparty-guard/shared';
import { CachedReceiverProvider, FixtureProvider, JsonTransport, LiveReceiverProvider, NearBlocksClient, NearRpcClient, ProviderError, codeIdentity } from './index.js';

const CODE_HASH = codeIdentity(Buffer.from('AGFzbQ==', 'base64'));
const NOW = 1_794_096_000_000;
const hash = createHash('sha256').update('fixture').digest('hex');
const action = { kind: 'transfer_near', receiver_id: 'merchant.testnet', amount_yocto: '1' } as const;
const cv = { complete: true, truncated: false, pages: 1, window_start_ms: null, window_end_ms: null, notes: [] };
function fixture(): ReceiverEvidence {
  return { network: 'testnet', source_mode: 'fixture', account_id: action.receiver_id, exists: true, code_identity: null, account_age_days: 30, recent_deployment: false, independent_successful_counterparties: 3, transfer_count: 3, activity_manipulation_score: 0, observations: [{ id: 'fixture-account', kind: 'account_state', network: 'testnet', source_mode: 'fixture', source: 'fixture', fetched_at: NOW, source_timestamp: NOW, block_height: '1', block_hash: 'fixture-block', coverage: cv, raw_hash: hash, value: { fixture: true } }], coverage: cv, observed_at: NOW };
}
function json(value: unknown, status = 200): Response { return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } }); }
function rpcFetch(options: { stale?: boolean; future?: boolean; network?: string; malformed?: boolean; code?: boolean; global?: boolean; mismatch?: boolean } = {}): typeof fetch {
  return (async (_input: unknown, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body)) as { method: string; params: Record<string, unknown> };
    let result: unknown;
    if (request.method === 'status') result = { chain_id: options.network ?? 'testnet' };
    else if (request.method === 'block') result = { header: { hash: 'block-hash', height: '42', timestamp_nanosec: String(BigInt(NOW - (options.stale ? 61_000 : options.future ? -1 : 500)) * 1_000_000n) } };
    else if (request.params.request_type === 'view_code') result = { block_hash: options.mismatch ? 'wrong-block' : 'block-hash', block_height: '42', code_base64: 'AGFzbQ==', hash: CODE_HASH };
    else result = { block_hash: 'block-hash', block_height: options.malformed ? 1.25 : 42, amount: '1', locked: '0', storage_usage: 123, code_hash: options.code ? CODE_HASH : '11111111111111111111111111111111', ...(options.global ? { global_account_id: 'owner.testnet' } : {}) };
    return json({ jsonrpc: '2.0', result });
  }) as typeof fetch;
}
function receipt(id = 'receipt-1', from = 'alice.testnet', to: string = action.receiver_id, success = true): Record<string, unknown> {
  return { receipt_id: id, transaction_hash: 'transaction-1', predecessor_account_id: from, receiver_account_id: to, actions: [{ action: 'TRANSFER', method: null }], actions_agg: { deposit: '10000000000000000000000' }, outcome: { status: success }, block: { block_hash: 'block-indexed', block_height: '41', block_timestamp: String(BigInt(NOW - 1000) * 1_000_000n) } };
}
function indexerFetch(receipts: unknown[], extra: { next?: string; accountCreated?: unknown; failure?: number } = {}): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    if (extra.failure) return json({}, extra.failure);
    if (url.pathname.endsWith('/receipts')) return json({ data: receipts, ...(extra.next ? { meta: { next_page: extra.next } } : {}) });
    if (url.pathname.endsWith('/deployments')) return json({ data: [] });
    const account = decodeURIComponent(url.pathname.split('/').pop()!);
    return json({ data: { account_id: account, created: extra.accountCreated ?? {}, deleted: {} } });
  }) as typeof fetch;
}

describe('required RPC state', () => {
  it('anchors account and code to one finalized block and retains actual block time', async () => {
    const rpc = new NearRpcClient({ url: 'https://rpc.example', network: 'testnet', clock: () => NOW, fetch: rpcFetch({ code: true }), minIntervalMs: 0 });
    const state = await rpc.getAccount('testnet', action.receiver_id);
    expect(state.code_identity).toBe(CODE_HASH);
    expect(state.observations.map((o) => o.kind)).toEqual(['account_state', 'contract_code']);
    expect(state.observations.every((o) => o.block_hash === 'block-hash' && o.source_timestamp === NOW - 500)).toBe(true);
    expect(state.observations[1]!.value).toHaveProperty('code_base64', 'AGFzbQ==');
    for (const observation of state.observations) expect(createHash('sha256').update(canonicalJson(JSON.parse(canonicalJson(observation.value)))).digest('hex')).toBe(observation.raw_hash);
  });
  it.each([{ stale: true }, { future: true }, { malformed: true }, { network: 'mainnet' }, { code: true, mismatch: true }])('fails closed for invalid state %j', async (options) => {
    const rpc = new NearRpcClient({ url: 'https://rpc.example', network: 'testnet', clock: () => NOW, fetch: rpcFetch(options), minIntervalMs: 0 });
    await expect(rpc.getAccount('testnet', action.receiver_id)).rejects.toBeInstanceOf(ProviderError);
  });
  it('rejects unsupported global code for calls without inventing local code identity', async () => {
    const rpc = new NearRpcClient({ url: 'https://rpc.example', network: 'testnet', clock: () => NOW, fetch: rpcFetch({ global: true }), minIntervalMs: 0 });
    const provider = new LiveReceiverProvider({ rpc, clock: () => NOW });
    await expect(provider.assess({ network: 'testnet', account_id: action.receiver_id, action: { kind: 'contract_call', receiver_id: action.receiver_id, method_name: 'record', args_base64: '', gas_tgas: 1, attached_deposit_yocto: '0' } })).rejects.toMatchObject({ code: 'UNSUPPORTED_CODE' });
  });
  it('keeps missing optional history explicit with zero independent credit', async () => {
    const rpc = new NearRpcClient({ url: 'https://rpc.example', network: 'testnet', clock: () => NOW, fetch: rpcFetch(), minIntervalMs: 0 });
    const evidence = await new LiveReceiverProvider({ rpc, clock: () => NOW }).assess({ network: 'testnet', account_id: action.receiver_id, action });
    expect(evidence.account_age_days).toBeNull();
    expect(evidence.independent_successful_counterparties).toBe(0);
    expect(evidence.coverage.complete).toBe(false);
    expect(evidence.observations[0]!.source_mode).toBe('live-testnet');
  });
});

describe('NearBlocks v3 contextual history', () => {
  it('uses v3 data/meta envelopes and deduplicates successful transfer receipts', async () => {
    const client = new NearBlocksClient({ clock: () => NOW, fetch: indexerFetch([receipt(), receipt(), receipt('failed', 'bad.testnet', action.receiver_id, false)]), minIntervalMs: 0, maxHops: 1 });
    const result = await client.collect('testnet', action.receiver_id);
    expect(result.edges).toHaveLength(1);
    expect(result.account_age_days).toBeNull();
    expect(result.observations.some((o) => o.kind === 'transfer_graph')).toBe(true);
    expect(result.observations.find((o) => o.kind === 'receipts')!.block_height).toBe('41');
  });
  it('exposes page truncation and treats next cursors as opaque', async () => {
    const seen: string[] = [];
    const base = indexerFetch([receipt()], { next: 'opaque+/=cursor' });
    const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => { seen.push(String(input)); return base(input, init); }) as typeof fetch;
    const result = await new NearBlocksClient({ clock: () => NOW, fetch: fetcher, minIntervalMs: 0, maxHops: 1, maxPages: 2 }).collect('testnet', action.receiver_id);
    expect(result.coverage.truncated).toBe(true);
    expect(result.coverage.pages).toBe(2);
    expect(seen.some((url) => new URL(url).searchParams.get('next') === 'opaque+/=cursor')).toBe(true);
  });
  it('bounds graph edges/nodes and does not credit zero, failed or function-call deposits', async () => {
    const fc = { ...receipt('fc'), actions: [{ action: 'FUNCTION_CALL' }] };
    const zero = { ...receipt('zero'), actions_agg: { deposit: '0' } };
    const result = await new NearBlocksClient({ clock: () => NOW, fetch: indexerFetch([receipt(), receipt('second', 'bob.testnet'), fc, zero]), minIntervalMs: 0, maxHops: 1, maxEdges: 1 }).collect('testnet', action.receiver_id);
    expect(result.edges).toHaveLength(1);
    expect(result.coverage.truncated).toBe(true);
  });
  it('stops graph traversal at the configured relationship boundary and exposes it', async () => {
    const receiptQueries: string[] = [];
    const fetcher = (async (input: RequestInfo | URL) => {
      const url = new URL(String(input));
      if (url.pathname.endsWith('/deployments')) return json({ data: [] });
      if (!url.pathname.endsWith('/receipts')) return json({ data: { account_id: action.receiver_id, created: {}, deleted: {} } });
      const account = url.pathname.split('/')[3]!;
      receiptQueries.push(account);
      return json({ data: account === action.receiver_id ? [receipt('root-edge')] : [receipt('next-edge', 'alice.testnet', 'bob.testnet')] });
    }) as typeof fetch;
    const result = await new NearBlocksClient({ clock: () => NOW, fetch: fetcher, minIntervalMs: 0, maxHops: 2 }).collect('testnet', action.receiver_id);
    expect(receiptQueries).toEqual([action.receiver_id, 'alice.testnet']);
    expect(result.edges).toHaveLength(2);
    expect(result.coverage.truncated).toBe(true);
    expect(result.coverage.notes.join(' ')).toContain('relationship-depth');
  });
  it('aborts an entire optional history collection at its deadline without further retries', async () => {
    let calls = 0;
    const fetcher = ((_input: unknown, init?: RequestInit) => {
      calls++;
      return new Promise((_resolve, reject) => { init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true }); });
    }) as typeof fetch;
    const result = await new NearBlocksClient({ clock: () => NOW, fetch: fetcher, maxDurationMs: 10, timeoutMs: 100, attempts: 3, minIntervalMs: 0 }).collect('testnet', action.receiver_id);
    expect(calls).toBe(1);
    expect(result.coverage.truncated).toBe(true);
    expect(result.coverage.notes.join(' ')).toContain('deadline');
    expect(result.edges).toEqual([]);
  });
  it('keeps outage and malformed optional history unknown', async () => {
    const result = await new NearBlocksClient({ clock: () => NOW, fetch: indexerFetch([], { failure: 401 }), attempts: 1, minIntervalMs: 0 }).collect('testnet', action.receiver_id);
    expect(result.edges).toEqual([]);
    expect(result.account_age_days).toBeNull();
    expect(result.coverage.complete).toBe(false);
    expect(result.coverage.notes.join(' ')).toContain('unavailable');
  });
  it('does not turn a creation lower bound or deleted lifecycle into an exact age', async () => {
    const fetcher = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/deployments') || url.includes('/receipts')) return json({ data: [] });
      return json({ data: { account_id: action.receiver_id, created: { block_timestamp: String(BigInt(NOW - 10_000) * 1_000_000n) }, deleted: { transaction_hash: 'older-delete' } } });
    }) as typeof fetch;
    const result = await new NearBlocksClient({ clock: () => NOW, fetch: fetcher, minIntervalMs: 0 }).collect('testnet', action.receiver_id);
    expect(result.account_age_days).toBeNull();
  });
});

describe('bounded transport and cache', () => {
  it('retries a rate limit only within budget and never exposes authorization in errors', async () => {
    let calls = 0;
    const sleeps: number[] = [];
    const transport = new JsonTransport({ fetch: (async () => { calls++; return json({}, 429); }) as typeof fetch, sleep: async (ms) => { sleeps.push(ms); }, attempts: 2, minIntervalMs: 0 });
    await expect(transport.request(new URL('https://source.example'))).rejects.toMatchObject({ code: 'SOURCE_UNAVAILABLE' });
    expect(calls).toBe(2);
    expect(sleeps).toEqual([250]);
  });
  it('spaces concurrent transport requests through a bounded queue', async () => {
    let now = 0;
    const requestTimes: number[] = [];
    const transport = new JsonTransport({ clock: () => now, sleep: async (ms) => { now += ms; }, minIntervalMs: 10, fetch: (async () => { requestTimes.push(now); return json({ ok: true }); }) as typeof fetch });
    await Promise.all([1, 2, 3].map(() => transport.request(new URL('https://source.example'))));
    expect(requestTimes).toEqual([0, 10, 20]);
  });
  it('rejects oversized and malformed JSON without retrying it into success', async () => {
    const transport = new JsonTransport({ fetch: (async () => new Response('abcdef')) as typeof fetch, maxResponseBytes: 3, minIntervalMs: 0 });
    await expect(transport.request(new URL('https://source.example'))).rejects.toMatchObject({ code: 'SOURCE_MALFORMED' });
  });
  it('times out stalled network requests using an abort signal', async () => {
    const fetcher = ((_input: unknown, init?: RequestInit) => new Promise((_resolve, reject) => { init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true }); })) as typeof fetch;
    const transport = new JsonTransport({ fetch: fetcher, timeoutMs: 5, attempts: 1, minIntervalMs: 0 });
    await expect(transport.request(new URL('https://source.example'))).rejects.toMatchObject({ code: 'SOURCE_UNAVAILABLE' });
  });
  it('evicts prior clean evidence after a failed forced refresh', async () => {
    let unavailable = false;
    const inner = new FixtureProvider([fixture()]);
    const provider = new CachedReceiverProvider({ sourceMode: 'fixture', assess: async (input) => { if (unavailable) throw new ProviderError('SOURCE_UNAVAILABLE', 'offline', 'fixture'); return inner.assess(input); } }, { clock: () => NOW });
    const input = { network: 'testnet', account_id: action.receiver_id, action } as const;
    await provider.assess(input);
    unavailable = true;
    await expect(provider.assess({ ...input, refresh: true })).rejects.toMatchObject({ code: 'SOURCE_UNAVAILABLE' });
    await expect(provider.assess(input)).rejects.toMatchObject({ code: 'SOURCE_UNAVAILABLE' });
  });
  it('separates fixture networks, preserves timestamps, clones cached values and refreshes explicitly', async () => {
    const inner = new FixtureProvider([fixture()]);
    let calls = 0;
    const provider = new CachedReceiverProvider({ sourceMode: 'fixture', assess: async (input) => { calls++; return inner.assess(input); } }, { clock: () => NOW });
    const input = { network: 'testnet', account_id: action.receiver_id, action } as const;
    const first = await provider.assess(input);
    first.exists = false;
    expect((await provider.assess(input)).exists).toBe(true);
    expect(calls).toBe(1);
    expect((await provider.assess({ ...input, refresh: true })).observed_at).toBe(NOW);
    expect(calls).toBe(2);
    await expect(provider.assess({ ...input, network: 'sandbox' })).rejects.toMatchObject({ code: 'SOURCE_UNAVAILABLE' });
  });
});
