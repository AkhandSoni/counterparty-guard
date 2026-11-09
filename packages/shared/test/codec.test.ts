import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { U128_MAX, U64_MAX, actionSchema, amountSchema, canonicalJson, checkRequestSchema, decodePermit, encodePermit, encodePublicKey, isPermitTimeValid, permitHash, permitSchema, permitSigningMessage, publicKeyFromKeyObject, publicKeySchema, revisionSchema, observationSchema, sha256, signPermit, verifySignedPermit, type Permit, type SignedPermit } from '../src/index.js';
const keys = generateKeyPairSync('ed25519');
const scorer = publicKeyFromKeyObject(keys.publicKey);
function sample(overrides: Partial<Permit> = {}): Permit {
  return { domain: 'CounterpartyGuard/Permit', version: 1, network: 'sandbox', deployment_instance_id: '11'.repeat(32), vault_id: 'vault.testnet', agent_account_id: 'agent.testnet', agent_public_key: scorer, action: { kind: 'transfer_near', receiver_id: 'receiver.testnet', amount_yocto: '10000000000000000000000' }, policy_revision: '1', blocklist_revision: '7', evidence_snapshot_hash: '22'.repeat(32), verdict: 'allow', nonce: '33'.repeat(32), issued_at: 1_800_000_000_000, expires_at: 1_800_000_120_000, ...overrides };
}
describe('strict JSON boundaries', () => {
  it('requires canonical bounded integer strings without throwing on malformed input', () => {
    for (const value of ['-1', '01', '1.0', '1e2', '', 'x', (U128_MAX + 1n).toString(), '9'.repeat(10_000)]) expect(amountSchema.safeParse(value).success).toBe(false);
    expect(amountSchema.parse(U128_MAX.toString())).toBe(U128_MAX.toString());
    expect(amountSchema.safeParse(1).success).toBe(false);
    expect(revisionSchema.safeParse((U64_MAX + 1n).toString()).success).toBe(false);
    expect(revisionSchema.safeParse('x').success).toBe(false);
  });
  it('rejects unknown identity fields and variants', () => {
    expect(checkRequestSchema.safeParse({ schema_version: 1, network: 'sandbox', vault_id: 'vault.testnet', request_id: 'test', agent_id: 'someone-else', action: sample().action }).success).toBe(false);
    expect(actionSchema.safeParse({ kind: 'transfer_token', receiver_id: 'receiver.testnet', amount_yocto: '1' }).success).toBe(false);
  });
  it('rejects malformed or noncanonical key and argument encodings', () => {
    expect(publicKeySchema.safeParse('ed25519:' + '1'.repeat(31)).success).toBe(false);
    expect(publicKeySchema.safeParse('ed25519:' + 'z'.repeat(44)).success).toBe(false);
    expect(publicKeySchema.parse(encodePublicKey(Buffer.alloc(32)))).toBe('ed25519:' + '1'.repeat(32));
    const action = { kind: 'contract_call', receiver_id: 'fixture.testnet', method_name: 'record', attached_deposit_yocto: '0', gas_tgas: 30 };
    for (const args_base64 of ['Zg', 'Zh==', 'Zg==\n', Buffer.alloc(4097).toString('base64')]) expect(actionSchema.safeParse({ ...action, args_base64 }).success).toBe(false);
    expect(actionSchema.parse({ ...action, args_base64: 'Zg==' })).toEqual({ ...action, args_base64: 'Zg==' });
  });
});
describe('Borsh permit integrity', () => {
  it('roundtrips both variants including raw arguments, zero and u128 maximum', () => {
    const call: Permit['action'] = { kind: 'contract_call', receiver_id: 'fixture.testnet', method_name: 'record', args_base64: Buffer.from('{ "memo" : "é" }').toString('base64'), attached_deposit_yocto: U128_MAX.toString(), gas_tgas: 300 };
    for (const permit of [sample(), sample({ action: { ...sample().action, kind: 'transfer_near', amount_yocto: '0' } }), sample({ action: call, verdict: 'warn' })]) expect(decodePermit(encodePermit(permit))).toEqual(permit);
  });
  it('rejects unknown tags, malformed lengths, truncation and trailing bytes', () => {
    const bytes = encodePermit(sample());
    for (let length = 0; length < bytes.length; length++) expect(() => decodePermit(bytes.subarray(0, length))).toThrow();
    expect(() => decodePermit(Buffer.concat([bytes, Buffer.from([0])]))).toThrow('Trailing');
    const badLength = Buffer.from(bytes); badLength.writeUInt32LE(0xffffffff, 0);
    expect(() => decodePermit(badLength)).toThrow('Oversized');
    const badNetwork = Buffer.from(bytes); badNetwork[4 + Buffer.byteLength(sample().domain) + 2] = 2;
    expect(() => decodePermit(badNetwork)).toThrow('Unknown');
    expect(() => decodePermit(Buffer.alloc(8193))).toThrow('byte limit');
  });
  it('binds every field and validates against a trusted scorer key', () => {
    const permit = sample();
    const signed = signPermit(permit, keys.privateKey);
    expect(verifySignedPermit(signed, scorer)).toBe(true);
    const changes: Partial<Permit>[] = [
      { network: 'testnet' }, { deployment_instance_id: '44'.repeat(32) }, { vault_id: 'other.testnet' }, { agent_account_id: 'other.testnet' }, { agent_public_key: encodePublicKey(Buffer.alloc(32)) },
      { action: { kind: 'transfer_near', receiver_id: 'other.testnet', amount_yocto: '10000000000000000000000' } }, { action: { kind: 'transfer_near', receiver_id: 'receiver.testnet', amount_yocto: '2' } },
      { policy_revision: '2' }, { blocklist_revision: '8' }, { evidence_snapshot_hash: '55'.repeat(32) }, { verdict: 'warn' }, { nonce: '66'.repeat(32) }, { issued_at: permit.issued_at + 1 }, { expires_at: permit.expires_at + 1 }
    ];
    for (const change of changes) {
      const mutated = { ...permit, ...change };
      expect(permitHash(mutated)).not.toBe(signed.permit_hash);
      expect(verifySignedPermit({ ...signed, payload: mutated, permit_hash: permitHash(mutated) }, scorer)).toBe(false);
    }
    const other = generateKeyPairSync('ed25519');
    expect(verifySignedPermit(signed, publicKeyFromKeyObject(other.publicKey))).toBe(false);
    expect(verifySignedPermit({ ...signed, scorer_public_key: publicKeyFromKeyObject(other.publicKey) }, scorer)).toBe(false);
    expect(verifySignedPermit({ ...signed, signature_base64: '!'.repeat(88) }, scorer)).toBe(false);
  });
  it('binds method, exact argument bytes, deposit and gas separately', () => {
    const action = { kind: 'contract_call' as const, receiver_id: 'fixture.testnet', method_name: 'record', args_base64: Buffer.from('{"memo":"ok"}').toString('base64'), attached_deposit_yocto: '1', gas_tgas: 30 };
    const signed = signPermit(sample({ action }), keys.privateKey);
    for (const change of [{ receiver_id: 'other.testnet' }, { method_name: 'other' }, { args_base64: Buffer.from('{ "memo": "ok" }').toString('base64') }, { attached_deposit_yocto: '2' }, { gas_tgas: 31 }]) {
      const payload = { ...signed.payload, action: { ...action, ...change } };
      expect(verifySignedPermit({ ...signed, payload, permit_hash: permitHash(payload) }, scorer)).toBe(false);
    }
  });
  it('enforces lifetime bounds and separates cryptographic validity from time', () => {
    const permit = sample();
    const signed = signPermit(permit, keys.privateKey);
    expect(isPermitTimeValid(permit, permit.issued_at - 1)).toBe(false);
    expect(isPermitTimeValid(permit, permit.issued_at)).toBe(true);
    expect(isPermitTimeValid(permit, permit.expires_at)).toBe(false);
    expect(verifySignedPermit(signed, scorer)).toBe(true);
    for (const expires_at of [permit.issued_at, permit.issued_at - 1, permit.issued_at + 300_001]) expect(permitSchema.safeParse({ ...permit, expires_at }).success).toBe(false);
    expect(permitSchema.safeParse({ ...permit, verdict: 'block' }).success).toBe(false);
  });
  it('matches published bytes, hashes, signing messages and public-key signatures', () => {
    const vectors = JSON.parse(readFileSync(new URL('../vectors/permit-v1.json', import.meta.url), 'utf8')) as { vectors: { name: string; signed: SignedPermit; encoded_hex: string; signing_message_hex: string }[] };
    expect(vectors.vectors.length).toBeGreaterThanOrEqual(4);
    for (const vector of vectors.vectors) {
      expect(encodePermit(vector.signed.payload).toString('hex'), vector.name).toBe(vector.encoded_hex);
      expect(decodePermit(Buffer.from(vector.encoded_hex, 'hex'))).toEqual(vector.signed.payload);
      expect(permitHash(vector.signed.payload)).toBe(vector.signed.permit_hash);
      expect(permitSigningMessage(vector.signed.payload).toString('hex')).toBe(vector.signing_message_hex);
      expect(verifySignedPermit(vector.signed, vector.signed.scorer_public_key)).toBe(true);
    }
  });
  it('canonicalizes JSON evidence keys without silently coercing unsafe values', () => {
    expect(canonicalJson({ b: [1, 'x'], a: true })).toBe('{"a":true,"b":[1,"x"]}');
    expect(sha256(canonicalJson({ a: 1, b: 2 }))).toBe(sha256(canonicalJson({ b: 2, a: 1 })));
    for (const value of [undefined, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, 1n, new Date()]) expect(() => canonicalJson(value)).toThrow();
  });
});

describe('retained JSON evidence limits', () => {
  it('rejects cyclic, deeply nested, oversized and missing retained data', () => {
    const cyclic: { value?: unknown } = {}; cyclic.value = cyclic;
    let deep: unknown = 'leaf'; for (let depth = 0; depth < 34; depth++) deep = { value: deep };
    for (const value of [cyclic, deep, 'x'.repeat(2_097_153), Array.from({ length: 50_001 }, () => null), Array(1), Array(100_000_000)]) expect(() => canonicalJson(value)).toThrow();
    expect(observationSchema.safeParse({ id: 'test', kind: 'account_state', network: 'sandbox', source_mode: 'fixture', source: 'fixture:local', fetched_at: 1, source_timestamp: 1, block_height: '1', block_hash: 'block', coverage: { complete: true, truncated: false, pages: 1, window_start_ms: null, window_end_ms: null, notes: [] }, raw_hash: '11'.repeat(32) }).success).toBe(false);
  });
});
