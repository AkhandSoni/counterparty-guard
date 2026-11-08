import bs58 from 'bs58';
import nacl from 'tweetnacl';

export interface Ed25519KeyPair {
  publicKey: string; // ed25519:<base58>
  secretKey: Uint8Array;
}

export function formatPublicKey(raw: Uint8Array): string {
  return `ed25519:${bs58.encode(raw)}`;
}

export function parsePublicKey(pk: string): Uint8Array {
  const clean = pk.replace(/^ed25519:/, '');
  const bytes = bs58.decode(clean);
  if (bytes.length !== 32) {
    throw new Error(`Invalid Ed25519 public key byte length: expected 32, got ${bytes.length}`);
  }
  return bytes;
}

export function formatSignature(raw: Uint8Array): string {
  return `ed25519:${bs58.encode(raw)}`;
}

export function parseSignature(sig: string): Uint8Array {
  const clean = sig.replace(/^ed25519:/, '');
  const bytes = bs58.decode(clean);
  if (bytes.length !== 64) {
    throw new Error(`Invalid Ed25519 signature byte length: expected 64, got ${bytes.length}`);
  }
  return bytes;
}

export function generateKeyPair(): Ed25519KeyPair {
  const kp = nacl.sign.keyPair();
  return {
    publicKey: formatPublicKey(kp.publicKey),
    secretKey: kp.secretKey,
  };
}

export function signDetached(message: Uint8Array, secretKey: Uint8Array): string {
  const signatureBytes = nacl.sign.detached(message, secretKey);
  return formatSignature(signatureBytes);
}

export function verifyDetached(message: Uint8Array, signature: string, publicKey: string): boolean {
  try {
    const sigBytes = parseSignature(signature);
    const pubBytes = parsePublicKey(publicKey);
    return nacl.sign.detached.verify(message, sigBytes, pubBytes);
  } catch {
    return false;
  }
}
