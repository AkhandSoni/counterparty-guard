import { createPublicKey, type KeyObject } from 'node:crypto';
import { decodePublicKey, encodePublicKey } from './base58.js';
export { decodePublicKey, encodePublicKey } from './base58.js';
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export function publicKeyObject(value: string): KeyObject {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, decodePublicKey(value)]), type: 'spki', format: 'der' });
}
export function publicKeyFromKeyObject(value: KeyObject): string {
  const key = value.type === 'public' ? value : createPublicKey(value);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Expected Ed25519 key');
  const der = key.export({ type: 'spki', format: 'der' });
  if (der.length !== SPKI_PREFIX.length + 32 || !der.subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX)) throw new Error('Unexpected Ed25519 key encoding');
  return encodePublicKey(der.subarray(SPKI_PREFIX.length));
}
