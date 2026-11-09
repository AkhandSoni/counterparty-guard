/** Fixed-upstream transport; callers never pass user-supplied evidence URLs. */
export type Fetch = typeof globalThis.fetch;
export type Clock = () => number;
export type Sleep = (milliseconds: number) => Promise<void>;

export class ProviderError extends Error {
  readonly name = 'ProviderError';
  constructor(
    readonly code: 'SOURCE_UNAVAILABLE' | 'SOURCE_MALFORMED' | 'ACCOUNT_NOT_FOUND' | 'UNSUPPORTED_CODE' | 'NETWORK_MISMATCH' | 'SOURCE_STALE',
    message: string,
    readonly source: string,
    readonly retryable = false,
  ) { super(message); }
}

export interface HttpOptions {
  fetch?: Fetch;
  clock?: Clock;
  sleep?: Sleep;
  timeoutMs?: number;
  attempts?: number;
  minIntervalMs?: number;
  maxResponseBytes?: number;
}

export class JsonTransport {
  private readonly fetcher: Fetch;
  private readonly clock: Clock;
  private readonly sleep: Sleep;
  private readonly timeoutMs: number;
  private readonly attempts: number;
  private readonly minIntervalMs: number;
  private readonly maxResponseBytes: number;
  private nextRequestAt = 0;
  private queue: Promise<void> = Promise.resolve();

  constructor(options: HttpOptions = {}) {
    this.fetcher = options.fetch ?? globalThis.fetch;
    this.clock = options.clock ?? Date.now;
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.timeoutMs = boundedInt(options.timeoutMs ?? 5_000, 1, 30_000, 'timeoutMs');
    this.attempts = boundedInt(options.attempts ?? 2, 1, 3, 'attempts');
    this.minIntervalMs = boundedInt(options.minIntervalMs ?? 100, 0, 10_000, 'minIntervalMs');
    this.maxResponseBytes = boundedInt(options.maxResponseBytes ?? 2_000_000, 1, 8_000_000, 'maxResponseBytes');
  }

  private async rateLimit(): Promise<() => void> {
    const previous = this.queue;
    let release!: () => void;
    this.queue = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      const delay = Math.max(0, this.nextRequestAt - this.clock());
      if (delay) await this.sleep(delay);
      this.nextRequestAt = this.clock() + this.minIntervalMs;
      return release;
    } catch (error) { release(); throw error; }
  }

  async request(url: URL, init: RequestInit = {}): Promise<unknown> {
    for (let attempt = 0; attempt < this.attempts; attempt++) {
      if (init.signal?.aborted) throw new ProviderError('SOURCE_UNAVAILABLE', 'Source collection deadline exceeded', url.origin);
      const release = await this.rateLimit();
      if (init.signal?.aborted) { release(); throw new ProviderError('SOURCE_UNAVAILABLE', 'Source collection deadline exceeded', url.origin); }
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const pendingResponse = this.fetcher(url, { ...init, signal: init.signal ? AbortSignal.any([controller.signal, init.signal]) : controller.signal, redirect: 'error' });
        release();
        const response = await pendingResponse;
        if (!response.ok) {
          const retryable = response.status === 429 || response.status >= 500;
          if (retryable && attempt + 1 < this.attempts) {
            await response.body?.cancel();
            await this.sleep(Math.min(250 * 2 ** attempt, 1_000));
            continue;
          }
          throw new ProviderError('SOURCE_UNAVAILABLE', `Upstream returned HTTP ${response.status}`, url.origin, retryable);
        }
        const declaredLength = Number(response.headers.get('content-length'));
        if (declaredLength > this.maxResponseBytes) {
          await response.body?.cancel();
          throw new ProviderError('SOURCE_MALFORMED', 'Upstream response exceeds the byte limit', url.origin);
        }
        const reader = response.body?.getReader();
        if (!reader) throw new ProviderError('SOURCE_MALFORMED', 'Upstream returned no response body', url.origin);
        let bytes = 0;
        const chunks: Uint8Array[] = [];
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          bytes += value.byteLength;
          if (bytes > this.maxResponseBytes) {
            await reader.cancel();
            throw new ProviderError('SOURCE_MALFORMED', 'Upstream response exceeds the byte limit', url.origin);
          }
          chunks.push(value);
        }
        try { return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown; }
        catch { throw new ProviderError('SOURCE_MALFORMED', 'Upstream returned invalid JSON', url.origin); }
      } catch (error) {
        if (error instanceof ProviderError) throw error;
        if (init.signal?.aborted) throw new ProviderError('SOURCE_UNAVAILABLE', 'Source collection deadline exceeded', url.origin);
        if (attempt + 1 < this.attempts) {
          await this.sleep(Math.min(250 * 2 ** attempt, 1_000));
          continue;
        }
        throw new ProviderError('SOURCE_UNAVAILABLE', 'Upstream request failed or timed out', url.origin, true);
      } finally { release(); clearTimeout(timeout); }
    }
    throw new ProviderError('SOURCE_UNAVAILABLE', 'Upstream request exhausted its retry budget', url.origin, true);
  }
}

export function boundedInt(value: number, min: number, max: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new RangeError(`${label} outside supported bounds`);
  return value;
}

export function fixedBaseUrl(value: string, allowHttp = false): URL {
  const url = new URL(value);
  if ((url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) || url.username || url.password || url.search || url.hash) {
    throw new TypeError('Upstream URL must use HTTPS, have no credentials/query/fragment, and be operator-configured');
  }
  return url;
}

export function object(value: unknown, label: string, source: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new ProviderError('SOURCE_MALFORMED', `${label} must be an object`, source);
  return value as Record<string, unknown>;
}

export function unsigned(value: unknown, label: string, source: string): string {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return String(value);
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value) || value.length > 39) throw new ProviderError('SOURCE_MALFORMED', `${label} must be an unsigned integer`, source);
  return value;
}

export function textField(value: unknown, label: string, source: string, max = 256): string {
  if (typeof value !== 'string' || !value.length || value.length > max) throw new ProviderError('SOURCE_MALFORMED', `${label} must be a bounded string`, source);
  return value;
}
