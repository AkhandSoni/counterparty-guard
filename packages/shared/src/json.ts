/** Bounded deterministic JSON serialization for retained evidence and request fingerprints. */
export const MAX_RETAINED_JSON_BYTES = 2_097_152;
export const MAX_RETAINED_JSON_DEPTH = 32;
export const MAX_RETAINED_JSON_NODES = 50_000;
export function canonicalJson(value: unknown): string {
  let nodes = 0;
  let bytes = 0;
  const active = new WeakSet<object>();
  const encoder = new TextEncoder();
  const account = (text: string): string => {
    bytes += encoder.encode(text).length;
    if (bytes > MAX_RETAINED_JSON_BYTES) throw new Error('Retained JSON byte limit exceeded');
    return text;
  };
  const visit = (item: unknown, depth: number): string => {
    if (++nodes > MAX_RETAINED_JSON_NODES || depth > MAX_RETAINED_JSON_DEPTH) throw new Error('Retained JSON complexity limit exceeded');
    if (item === null || typeof item === 'boolean') return account(JSON.stringify(item));
    if (typeof item === 'string') {
      if (item.length > MAX_RETAINED_JSON_BYTES) throw new Error('Retained JSON string limit exceeded');
      return account(JSON.stringify(item));
    }
    if (typeof item === 'number') {
      if (!Number.isFinite(item) || (Number.isInteger(item) && !Number.isSafeInteger(item))) throw new Error('Invalid JSON number');
      return account(JSON.stringify(item));
    }
    if (typeof item !== 'object' || item === null || (!Array.isArray(item) && Object.getPrototypeOf(item) !== Object.prototype && Object.getPrototypeOf(item) !== null)) throw new Error('Expected JSON-only value');
    if (active.has(item)) throw new Error('Cyclic JSON value');
    active.add(item);
    let result: string;
    if (Array.isArray(item)) {
      if (item.length > MAX_RETAINED_JSON_NODES) throw new Error('Retained JSON array limit exceeded');
      account('[]' + ','.repeat(Math.max(0, item.length - 1)));
      const children: string[] = [];
      for (const child of item) children.push(visit(child, depth + 1));
      result = '[' + children.join(',') + ']';
    } else {
      const keys = Object.keys(item).sort();
      account('{}' + ','.repeat(Math.max(0, keys.length - 1)));
      result = '{' + keys.map(key => account(JSON.stringify(key) + ':') + visit((item as Record<string, unknown>)[key], depth + 1)).join(',') + '}';
    }
    active.delete(item);
    return result;
  };
  return visit(value, 0);
}
export function isBoundedJson(value: unknown): boolean {
  try { canonicalJson(value); return true; } catch { return false; }
}
