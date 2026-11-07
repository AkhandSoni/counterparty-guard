import { createHash } from 'node:crypto';
import { accountIdSchema, canonicalJson } from '@counterparty-guard/shared';
import type { Network, SourceObservation } from './types.js';
import { JsonTransport, ProviderError, boundedInt, fixedBaseUrl, object, unsigned, textField, type Clock, type HttpOptions } from './http.js';

const EMPTY_CODE_HASH = '11111111111111111111111111111111';
export interface RpcState { exists: boolean; code_identity: string | null; observed_at: number; observation: SourceObservation; observations: SourceObservation[] }
export interface RpcOptions extends HttpOptions { url: string; network: Network; allowLocalHttp?: boolean; maxBlockAgeMs?: number }

/** Current state is anchored to a finalized block, never the optimistic head. */
export class NearRpcClient {
  private readonly url: URL;
  private readonly transport: JsonTransport;
  private readonly clock: Clock;
  readonly network: Network;
  private readonly maxBlockAgeMs: number;
  constructor(options: RpcOptions) {
    this.network = options.network;
    this.maxBlockAgeMs = boundedInt(options.maxBlockAgeMs ?? 60_000, 1, 60_000, 'maxBlockAgeMs');
    this.url = fixedBaseUrl(options.url, options.allowLocalHttp ?? false);
    this.transport = new JsonTransport(options);
    this.clock = options.clock ?? Date.now;
    if (options.network === 'sandbox' && !options.allowLocalHttp) throw new TypeError('Sandbox RPC requires explicit allowLocalHttp');
  }
  private async rpc(method: string, params: unknown): Promise<Record<string, unknown>> {
    const response = object(await this.transport.request(this.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 'counterparty-guard', method, params }) }), 'RPC response', this.url.origin);
    if (response.error !== undefined) {
      const error = object(response.error, 'RPC error', this.url.origin);
      const cause = error.cause && typeof error.cause === 'object' ? error.cause as Record<string, unknown> : {};
      if (cause.name === 'UNKNOWN_ACCOUNT' || (typeof error.data === 'string' && error.data.includes('does not exist'))) throw new ProviderError('ACCOUNT_NOT_FOUND', 'Receiver account does not exist at the selected block', this.url.origin);
      throw new ProviderError('SOURCE_UNAVAILABLE', 'RPC could not establish required current state', this.url.origin, true);
    }
    return object(response.result, 'RPC result', this.url.origin);
  }
  async getAccount(network: Network, accountId: string): Promise<RpcState> {
    accountIdSchema.parse(accountId);
    if (network !== this.network) throw new ProviderError('NETWORK_MISMATCH', 'Configured RPC does not serve the requested network', this.url.origin);
    if (network === 'testnet') {
      const status = await this.rpc('status', []);
      if (status.chain_id !== 'testnet') throw new ProviderError('NETWORK_MISMATCH', 'RPC chain identity is not testnet', this.url.origin);
    }
    // Querying view_account with finality returns a concrete finalized block reference.
    const state = await this.rpc('query', { request_type: 'view_account', finality: 'final', account_id: accountId });
    const blockHash = textField(state.block_hash, 'block_hash', this.url.origin, 128);
    const blockHeight = unsigned(state.block_height, 'block_height', this.url.origin);
    unsigned(state.amount, 'amount', this.url.origin);
    unsigned(state.locked, 'locked', this.url.origin);
    unsigned(state.storage_usage, 'storage_usage', this.url.origin);
    const global = state.global_contract_hash !== undefined || state.global_contract_account_id !== undefined || state.global_code_hash !== undefined || state.global_account_id !== undefined;
    const codeHash = global && state.code_hash === undefined ? EMPTY_CODE_HASH : textField(state.code_hash, 'code_hash', this.url.origin, 128);
    const block = await this.rpc('block', { block_id: blockHash });
    const header = object(block.header, 'block header', this.url.origin);
    if (header.hash !== blockHash || unsigned(header.height, 'height', this.url.origin) !== blockHeight) throw new ProviderError('SOURCE_MALFORMED', 'RPC block reference does not match account query', this.url.origin);
    const ns = BigInt(unsigned(header.timestamp_nanosec ?? header.timestamp, 'block timestamp', this.url.origin));
    const sourceTimestamp = Number(ns / 1_000_000n);
    const observedAt = this.clock();
    if (!Number.isSafeInteger(sourceTimestamp) || sourceTimestamp > observedAt || observedAt - sourceTimestamp > this.maxBlockAgeMs) throw new ProviderError('SOURCE_STALE', 'Finalized block timestamp is stale or invalid', this.url.origin);
    let codeObservation: SourceObservation | undefined;
    if (!global && codeHash !== EMPTY_CODE_HASH) {
      const code = await this.rpc('query', { request_type: 'view_code', block_id: blockHash, account_id: accountId });
      if (code.block_hash !== blockHash || unsigned(code.block_height, 'code block_height', this.url.origin) !== blockHeight || code.hash !== codeHash) throw new ProviderError('SOURCE_MALFORMED', 'Contract code identity/block does not match the account query', this.url.origin);
      if (typeof code.code_base64 !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(code.code_base64)) throw new ProviderError('SOURCE_MALFORMED', 'Contract code is not canonical base64', this.url.origin);
      if (Buffer.from(code.code_base64, 'base64').toString('base64') !== code.code_base64 || codeIdentity(Buffer.from(code.code_base64, 'base64')) !== codeHash) throw new ProviderError('SOURCE_MALFORMED', 'Contract bytecode hash does not match its declared identity', this.url.origin);
      const codeHashRaw = createHash('sha256').update(canonicalJson(code)).digest('hex');
      codeObservation = { id: `rpc-code-${codeHashRaw.slice(0, 24)}`, kind: 'contract_code', network, source_mode: network === 'sandbox' ? 'fixture' : 'live-testnet', source: this.url.origin, fetched_at: this.clock(), source_timestamp: sourceTimestamp, block_height: blockHeight, block_hash: blockHash, coverage: { complete: true, truncated: false, pages: 1, window_start_ms: null, window_end_ms: null, notes: [] }, raw_hash: codeHashRaw, value: code };
    }
    const hash = createHash('sha256').update(canonicalJson(state)).digest('hex');
    const accountObservation: SourceObservation = {
        id: `rpc-account-${hash.slice(0, 24)}`,
        kind: 'account_state', network, source_mode: network === 'sandbox' ? 'fixture' : 'live-testnet', source: this.url.origin,
        fetched_at: observedAt, source_timestamp: sourceTimestamp, block_height: blockHeight, block_hash: blockHash,
        coverage: { complete: true, truncated: false, pages: 1, window_start_ms: null, window_end_ms: null, notes: global ? ['Unsupported global-code representation; no contract-call authorization.'] : [] },
        raw_hash: hash, value: state,
      };
    return {
      exists: true,
      // Global-code identity is deliberately unavailable until that representation is supported.
      code_identity: global || codeHash === EMPTY_CODE_HASH ? null : codeHash,
      observed_at: observedAt,
      observation: accountObservation, observations: codeObservation ? [accountObservation, codeObservation] : [accountObservation],
    };
  }
  async viewFunction(network: Network, accountId: string, methodName: string, args: unknown = {}, blockId?: string): Promise<{ value: unknown; block_height: string; block_hash: string; observed_at: number; raw: Record<string, unknown> }> {
    accountIdSchema.parse(accountId);
    if (network !== this.network) throw new ProviderError('NETWORK_MISMATCH', 'Configured RPC does not serve the requested network', this.url.origin);
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(methodName)) throw new TypeError('Invalid view method');
    const result = await this.rpc('query', { request_type: 'call_function', account_id: accountId, method_name: methodName, args_base64: Buffer.from(JSON.stringify(args)).toString('base64'), ...(blockId ? { block_id: blockId } : { finality: 'final' }) });
    if (!Array.isArray(result.result) || result.result.length > 65_536 || result.result.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) throw new ProviderError('SOURCE_MALFORMED', 'Invalid bounded view result bytes', this.url.origin);
    let value: unknown;
    try { value = JSON.parse(Buffer.from(result.result as number[]).toString('utf8')) as unknown; }
    catch { throw new ProviderError('SOURCE_MALFORMED', 'View did not return JSON', this.url.origin); }
    return { value, block_height: unsigned(result.block_height, 'block_height', this.url.origin), block_hash: textField(result.block_hash, 'block_hash', this.url.origin, 128), observed_at: this.clock(), raw: result };
  }
}

/** NEAR local-code identity is base58(SHA256(exact WASM bytes)). */
export function codeIdentity(bytes: Uint8Array): string {
  const digest = createHash('sha256').update(bytes).digest();
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let number = BigInt(`0x${digest.toString('hex')}`);
  let result = '';
  while (number) { result = alphabet[Number(number % 58n)]! + result; number /= 58n; }
  for (const byte of digest) { if (byte !== 0) break; result = '1' + result; }
  return result;
}
