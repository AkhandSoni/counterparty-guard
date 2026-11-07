import { createHash, sign, verify, type KeyObject } from 'node:crypto';
import { MAX_PERMIT_BYTES, PERMIT_DOMAIN, SIGNING_DOMAIN, permitSchema, signedPermitSchema, type Action, type Permit, type SignedPermit } from '../schemas.js';
import { decodePublicKey, encodePublicKey, publicKeyFromKeyObject, publicKeyObject } from './keys.js';
export { decodePublicKey, encodePublicKey, publicKeyFromKeyObject } from './keys.js';

class Writer {
  readonly chunks: Buffer[] = [];
  integer(value: bigint | number, width: number): void {
    let integer = BigInt(value);
    if (integer < 0n || integer >= (1n << BigInt(width * 8))) throw new Error('Integer out of bounds');
    const bytes = Buffer.alloc(width);
    for (let index = 0; index < width; index++) { bytes[index] = Number(integer & 255n); integer >>= 8n; }
    this.chunks.push(bytes);
  }
  bytes(value: Uint8Array): void { this.chunks.push(Buffer.from(value)); }
  vector(value: Uint8Array): void { this.integer(value.length, 4); this.bytes(value); }
  string(value: string): void { this.vector(Buffer.from(value, 'utf8')); }
  result(): Buffer {
    const result = Buffer.concat(this.chunks);
    if (result.length > MAX_PERMIT_BYTES) throw new Error('Permit exceeds byte limit');
    return result;
  }
}
class Reader {
  private offset = 0;
  constructor(private readonly bytes: Buffer) {
    if (bytes.length > MAX_PERMIT_BYTES) throw new Error('Permit exceeds byte limit');
  }
  fixed(length: number): Buffer {
    if (length > this.bytes.length - this.offset) throw new Error('Truncated permit');
    const result = this.bytes.subarray(this.offset, this.offset + length); this.offset += length; return result;
  }
  integer(width: number): bigint {
    const bytes = this.fixed(width);
    let result = 0n;
    for (let index = bytes.length - 1; index >= 0; index--) result = result * 256n + BigInt(bytes[index]!);
    return result;
  }
  number(width: number): number {
    const integer = this.integer(width);
    if (integer > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Unsafe JSON integer');
    return Number(integer);
  }
  vector(max: number): Buffer {
    const length = this.number(4);
    if (length > max) throw new Error('Oversized field');
    return this.fixed(length);
  }
  string(max: number): string {
    return new TextDecoder('utf-8', { fatal: true }).decode(this.vector(max));
  }
  done(): void { if (this.offset !== this.bytes.length) throw new Error('Trailing permit bytes'); }
}
function writeAction(writer: Writer, action: Action): void {
  writer.integer(action.kind === 'transfer_near' ? 0 : 1, 1);
  writer.string(action.receiver_id);
  if (action.kind === 'transfer_near') writer.integer(BigInt(action.amount_yocto), 16);
  else {
    writer.string(action.method_name);
    writer.vector(Buffer.from(action.args_base64, 'base64'));
    writer.integer(BigInt(action.attached_deposit_yocto), 16);
    writer.integer(action.gas_tgas, 8);
  }
}
function readAction(reader: Reader): Action {
  const tag = reader.number(1);
  if (tag !== 0 && tag !== 1) throw new Error('Unknown action variant');
  const receiver_id = reader.string(64);
  if (tag === 0) return { kind: 'transfer_near', receiver_id, amount_yocto: reader.integer(16).toString() };
  return { kind: 'contract_call', receiver_id, method_name: reader.string(64), args_base64: reader.vector(4096).toString('base64'), attached_deposit_yocto: reader.integer(16).toString(), gas_tgas: reader.number(8) };
}
export function encodePermit(input: Permit): Buffer {
  const permit = permitSchema.parse(input);
  const writer = new Writer();
  writer.string(permit.domain);
  writer.integer(permit.version, 2);
  writer.integer(permit.network === 'sandbox' ? 0 : 1, 1);
  writer.bytes(Buffer.from(permit.deployment_instance_id, 'hex'));
  writer.string(permit.vault_id);
  writer.string(permit.agent_account_id);
  writer.bytes(decodePublicKey(permit.agent_public_key));
  writeAction(writer, permit.action);
  writer.integer(BigInt(permit.policy_revision), 8);
  writer.integer(BigInt(permit.blocklist_revision), 8);
  writer.bytes(Buffer.from(permit.evidence_snapshot_hash, 'hex'));
  writer.integer(permit.verdict === 'allow' ? 0 : 1, 1);
  writer.bytes(Buffer.from(permit.nonce, 'hex'));
  writer.integer(permit.issued_at, 8);
  writer.integer(permit.expires_at, 8);
  return writer.result();
}
export function decodePermit(bytes: Uint8Array): Permit {
  const reader = new Reader(Buffer.from(bytes));
  const domain = reader.string(64);
  const version = reader.number(2);
  const networkTag = reader.number(1);
  if (domain !== PERMIT_DOMAIN || version !== 1 || networkTag > 1) throw new Error('Unknown permit domain/version/network');
  const deployment_instance_id = reader.fixed(32).toString('hex');
  const vault_id = reader.string(64);
  const agent_account_id = reader.string(64);
  const agent_public_key = encodePublicKey(reader.fixed(32));
  const action = readAction(reader);
  const policy_revision = reader.integer(8).toString();
  const blocklist_revision = reader.integer(8).toString();
  const evidence_snapshot_hash = reader.fixed(32).toString('hex');
  const verdictTag = reader.number(1);
  if (verdictTag > 1) throw new Error('Unknown permit verdict');
  const nonce = reader.fixed(32).toString('hex');
  const issued_at = reader.number(8);
  const expires_at = reader.number(8);
  reader.done();
  return permitSchema.parse({ domain, version, network: networkTag === 0 ? 'sandbox' : 'testnet', deployment_instance_id, vault_id, agent_account_id, agent_public_key, action, policy_revision, blocklist_revision, evidence_snapshot_hash, verdict: verdictTag === 0 ? 'allow' : 'warn', nonce, issued_at, expires_at });
}
export function sha256(bytes: Uint8Array | string): string { return createHash('sha256').update(bytes).digest('hex'); }
export function permitHash(permit: Permit): string { return sha256(encodePermit(permit)); }
export function permitSigningMessage(permit: Permit): Buffer { return Buffer.concat([Buffer.from(SIGNING_DOMAIN, 'utf8'), Buffer.from(permitHash(permit), 'hex')]); }
export function signPermit(input: Permit, privateKey: KeyObject): SignedPermit {
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') throw new Error('Expected private Ed25519 scorer key');
  const payload = permitSchema.parse(input);
  return { payload, permit_hash: permitHash(payload), signature_base64: sign(null, permitSigningMessage(payload), privateKey).toString('base64'), scorer_public_key: publicKeyFromKeyObject(privateKey) };
}
/** expectedScorerKey must come from trusted deployment configuration, never the envelope itself. */
export function verifySignedPermit(input: SignedPermit, expectedScorerKey: string): boolean {
  try {
    const signed = signedPermitSchema.parse(input);
    if (signed.scorer_public_key !== expectedScorerKey || signed.permit_hash !== permitHash(signed.payload)) return false;
    const signature = Buffer.from(signed.signature_base64, 'base64');
    if (signature.length !== 64 || signature.toString('base64') !== signed.signature_base64) return false;
    return verify(null, permitSigningMessage(signed.payload), publicKeyObject(expectedScorerKey), signature);
  } catch { return false; }
}
/** Time validity is separate from signature integrity; chain code must also check its own clock. */
export function isPermitTimeValid(permit: Permit, now: number): boolean {
  return Number.isSafeInteger(now) && permitSchema.safeParse(permit).success && now >= permit.issued_at && now < permit.expires_at;
}
export { canonicalJson } from '../json.js';
