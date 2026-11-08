import { describe, expect, it } from 'vitest';
import { generateKeyPair, parsePublicKey, signDetached } from '../src/crypto/ed25519.js';
import {
  type ReportSignablePayload,
  serializeReportForSigning,
  signReportPayload,
  verifyReportSignature,
} from '../src/crypto/report-signing.js';

describe('Ed25519 Cryptography & Domain Separation', () => {
  const samplePayload: ReportSignablePayload = {
    network: 'testnet',
    accused_account_id: 'bad-actor.testnet',
    reporter_id: 'sentinel.testnet',
    reporter_public_key: '', // will be set dynamically
    category: 'drainer',
    description: 'Unauthorized sweep of contract balance using exploit permit.',
    transaction_references: ['9XyZ1234567890abcdef', '1AbCdEfGhIjKlMnOpQrS'],
    evidence_content_hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    contract_code_hash: null,
    issued_at: 1700000000000,
    expires_at: 1700604800000,
    nonce: 'nonce-uuid-deterministic-1234',
  };

  it('generates valid Ed25519 keypairs with 32-byte public and 64-byte secret keys', () => {
    const keyPair = generateKeyPair();
    expect(keyPair.publicKey).toMatch(/^ed25519:[1-9A-HJ-NP-Za-km-z]{43,44}$/);
    expect(keyPair.secretKey.length).toBe(64);

    const pubBytes = parsePublicKey(keyPair.publicKey);
    expect(pubBytes.length).toBe(32);
  });

  it('produces deterministic Borsh canonical serialization regardless of field property order', () => {
    const keyPair = generateKeyPair();
    const payloadA: ReportSignablePayload = {
      ...samplePayload,
      reporter_public_key: keyPair.publicKey,
    };
    // Reorder object keys in payloadB
    const payloadB: ReportSignablePayload = {
      nonce: payloadA.nonce,
      expires_at: payloadA.expires_at,
      issued_at: payloadA.issued_at,
      contract_code_hash: payloadA.contract_code_hash,
      evidence_content_hashes: payloadA.evidence_content_hashes,
      transaction_references: payloadA.transaction_references,
      description: payloadA.description,
      category: payloadA.category,
      reporter_public_key: payloadA.reporter_public_key,
      reporter_id: payloadA.reporter_id,
      accused_account_id: payloadA.accused_account_id,
      network: payloadA.network,
    };

    const bytesA = serializeReportForSigning(payloadA);
    const bytesB = serializeReportForSigning(payloadB);

    expect(bytesA).toEqual(bytesB);
  });

  it('signs and verifies a canonical report payload (Happy Path)', () => {
    const keyPair = generateKeyPair();
    const payload: ReportSignablePayload = {
      ...samplePayload,
      reporter_public_key: keyPair.publicKey,
    };

    const signature = signReportPayload(payload, keyPair.secretKey);
    expect(signature).toMatch(/^ed25519:[1-9A-HJ-NP-Za-km-z]{86,88}$/);

    const fullReport = {
      ...payload,
      signature,
    };

    const isValid = verifyReportSignature(fullReport);
    expect(isValid).toBe(true);
  });

  it('rejects tampered payload fields (Security Invariant)', () => {
    const keyPair = generateKeyPair();
    const payload: ReportSignablePayload = {
      ...samplePayload,
      reporter_public_key: keyPair.publicKey,
    };
    const signature = signReportPayload(payload, keyPair.secretKey);

    // Tampering 1: Change accused account
    expect(
      verifyReportSignature({ ...payload, accused_account_id: 'innocent.testnet', signature }),
    ).toBe(false);

    // Tampering 2: Change description
    expect(
      verifyReportSignature({ ...payload, description: 'Slightly altered description', signature }),
    ).toBe(false);

    // Tampering 3: Change category
    expect(verifyReportSignature({ ...payload, category: 'other', signature })).toBe(false);

    // Tampering 4: Alter timestamp
    expect(
      verifyReportSignature({ ...payload, issued_at: payload.issued_at + 1000, signature }),
    ).toBe(false);

    // Tampering 5: Alter nonce
    expect(
      verifyReportSignature({ ...payload, nonce: 'replayed-or-tampered-nonce', signature }),
    ).toBe(false);

    // Tampering 6: Inject extra reference
    expect(
      verifyReportSignature({
        ...payload,
        transaction_references: [...payload.transaction_references, 'extra_tx_hash_12345'],
        signature,
      }),
    ).toBe(false);
  });

  it('rejects cross-domain replay attacks (Domain Separator Invariant)', () => {
    const keyPair = generateKeyPair();
    const payload: ReportSignablePayload = {
      ...samplePayload,
      reporter_public_key: keyPair.publicKey,
    };

    // Attacker serializes report under unauthorized permit domain
    const crossDomainSerialized = serializeReportForSigning(
      payload,
      'COUNTERPARTY_GUARD_PERMIT_V1',
    );
    const forgedSignature = signDetached(crossDomainSerialized, keyPair.secretKey);

    const forgedReport = {
      ...payload,
      signature: forgedSignature,
    };

    // Must be rejected by standard report verifier
    expect(verifyReportSignature(forgedReport)).toBe(false);
  });

  it('rejects signatures from mismatched reporter public keys', () => {
    const legitimateSigner = generateKeyPair();
    const imposter = generateKeyPair();

    const payload: ReportSignablePayload = {
      ...samplePayload,
      reporter_public_key: imposter.publicKey, // Claims imposter key in payload
    };

    // Signed by legitimate signer's private key
    const signature = signReportPayload(payload, legitimateSigner.secretKey);

    const report = {
      ...payload,
      signature,
    };

    expect(verifyReportSignature(report)).toBe(false);
  });

  it('rejects corrupted or mutated signature strings gracefully without throwing unhandled exceptions', () => {
    const keyPair = generateKeyPair();
    const payload: ReportSignablePayload = {
      ...samplePayload,
      reporter_public_key: keyPair.publicKey,
    };
    const validSig = signReportPayload(payload, keyPair.secretKey);

    // Mutate signature
    const mutatedSig = `${validSig.slice(0, -4)}AAAA`;
    expect(verifyReportSignature({ ...payload, signature: mutatedSig })).toBe(false);

    // Corrupted signature format
    expect(verifyReportSignature({ ...payload, signature: 'invalid-non-base58' })).toBe(false);
  });

  it('rejects expired reports where expires_at <= issued_at', () => {
    const keyPair = generateKeyPair();
    const invalidTimesPayload: ReportSignablePayload = {
      ...samplePayload,
      reporter_public_key: keyPair.publicKey,
      issued_at: 1700604800000,
      expires_at: 1700000000000, // Inverted
    };
    const sig = signReportPayload(invalidTimesPayload, keyPair.secretKey);
    expect(verifyReportSignature({ ...invalidTimesPayload, signature: sig })).toBe(false);
  });
});
