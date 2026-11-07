const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function encodeBase58(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes) value = value * 256n + BigInt(byte);
  let result = '';
  while (value > 0n) { result = ALPHABET[Number(value % 58n)]! + result; value /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; result = '1' + result; }
  return result;
}
export function decodeBase58(value: string): Uint8Array {
  if (value.length > 44 || value.length === 0) throw new Error('Invalid Ed25519 key length');
  let integer = 0n;
  for (const character of value) {
    const digit = ALPHABET.indexOf(character);
    if (digit < 0) throw new Error('Invalid base58');
    integer = integer * 58n + BigInt(digit);
  }
  const bytes: number[] = [];
  while (integer > 0n) { bytes.unshift(Number(integer % 256n)); integer /= 256n; }
  let leading = 0;
  while (value[leading] === '1') leading++;
  const result = new Uint8Array(leading + bytes.length);
  result.set(bytes, leading);
  if (result.length !== 32 || encodeBase58(result) !== value) throw new Error('Expected canonical 32-byte Ed25519 key');
  return result;
}
export function decodePublicKey(value: string): Uint8Array {
  if (!value.startsWith('ed25519:')) throw new Error('Only Ed25519 keys are supported');
  return decodeBase58(value.slice(8));
}
export function encodePublicKey(raw: Uint8Array): string {
  if (raw.length !== 32) throw new Error('Expected 32-byte Ed25519 key');
  return 'ed25519:' + encodeBase58(raw);
}
