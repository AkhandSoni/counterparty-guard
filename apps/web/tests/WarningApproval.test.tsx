import React from 'react';
import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import {
  WarningApproval,
  isValidNearAccountId,
  validatePermitHash,
} from '../src/views/WarningApproval';

describe('WarningApproval Component (apps/web/views/WarningApproval)', () => {
  describe('1. Default Rendering & Security Invariant Banner', () => {
    it('renders with default props and shows mandatory human-in-the-loop security banner', () => {
      const html = renderToString(<WarningApproval />);

      // Invariant Banner assertions
      expect(html).toContain('Owner Warning Approval Required (Human-in-the-Loop)');
      expect(html).toContain('Automated agents cannot sign value transfers under a');
      expect(html).toContain('WARN');
      expect(html).toContain(
        'Security Invariant: A browser UI button or LLM prompt has ZERO authority to execute',
      );
      expect(html).toContain(
        'Only an on-chain transaction signed by the recovery owner key authorizes execution',
      );
    });

    it('renders default parameter values and status indicators', () => {
      const html = renderToString(<WarningApproval />);

      expect(html).toContain('vault.agent-c.testnet');
      expect(html).toContain('new-vendor.testnet');
      expect(html).toContain('0.05 NEAR');
      expect(html).toContain('50000000000000000000000 yoctoNEAR');
      expect(html).toContain('RECENT_DEPLOYMENT');
      expect(html).toContain('Parameters Validated');
      expect(html).toContain('Awaiting on-chain owner call to vault.approve_warn...');
    });
  });

  describe('2. Exact NEAR CLI Command Conformance', () => {
    it('generates exact copyable NEAR CLI command with all required flags', () => {
      const defaultHash = '9b8e21a0f54318c39e2d765418b7654321908765432109876543210987654321';
      const html = renderToString(<WarningApproval />);

      // Conformance to: near contract call-function as-transaction <vault> approve_warn ...
      expect(html).toContain(
        'near contract call-function as-transaction vault.agent-c.testnet approve_warn',
      );
      expect(html).toContain(
        `json-args &#x27;{&quot;permit_hash&quot;:&quot;${defaultHash}&quot;}&#x27;`,
      );
      expect(html).toContain('prepaid-gas &#x27;100.0 Tgas&#x27;');
      expect(html).toContain('attached-deposit &#x27;0 NEAR&#x27;');
      expect(html).toContain('sign-as owner.testnet');
      expect(html).toContain('network-config testnet');
    });

    it('generates exact CLI command with custom initialNetwork and initialOwnerAccount', () => {
      const html = renderToString(
        <WarningApproval
          initialNetwork="mainnet"
          initialOwnerAccount="treasury-recovery.near"
          context={{
            permitHash: '1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff',
            vaultAccountId: 'enterprise-vault.near',
            receiverAccountId: 'partner.near',
            amountNear: '50.0',
            reasonCodes: ['POLICY_LIMIT_EXCEEDED'],
          }}
        />,
      );

      expect(html).toContain(
        'near contract call-function as-transaction enterprise-vault.near approve_warn',
      );
      expect(html).toContain('sign-as treasury-recovery.near');
      expect(html).toContain('network-config mainnet');
      expect(html).toContain('1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff');
      expect(html).toContain('50.0 NEAR');
      expect(html).toContain('50000000000000000000000000 yoctoNEAR');
    });
  });

  describe('3. Account ID & Permit Hash Validation Logic', () => {
    it('accurately validates standard named and implicit NEAR account IDs', () => {
      // Valid cases
      expect(isValidNearAccountId('alice.near')).toBe(true);
      expect(isValidNearAccountId('vault.agent-c.testnet')).toBe(true);
      expect(isValidNearAccountId('sub_account.vendor-1.testnet')).toBe(true);
      expect(isValidNearAccountId('a'.repeat(64))).toBe(true); // 64-char hex implicit account
      expect(
        isValidNearAccountId('1234567890123456789012345678901234567890123456789012345678901234'),
      ).toBe(true);

      // Invalid cases
      expect(isValidNearAccountId('')).toBe(false);
      expect(isValidNearAccountId('a')).toBe(false); // < 2 chars
      expect(isValidNearAccountId('a'.repeat(65))).toBe(false); // > 64 chars
      expect(isValidNearAccountId('Alice.testnet')).toBe(false); // uppercase not allowed
      expect(isValidNearAccountId('bad@account.testnet')).toBe(false); // special char @
      expect(isValidNearAccountId('-start-with-hyphen.testnet')).toBe(false);
      expect(isValidNearAccountId('.start-with-dot.testnet')).toBe(false);
    });

    it('normalizes 0x-prefixed permit hashes and validates 64-char lowercase hex strictly', () => {
      const validCanonical = '7a8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b';
      const valid0x = `0x${validCanonical}`;

      const resCanonical = validatePermitHash(validCanonical);
      expect(resCanonical.isValid).toBe(true);
      expect(resCanonical.canonicalHash).toBe(validCanonical);

      const res0x = validatePermitHash(valid0x);
      expect(res0x.isValid).toBe(true);
      expect(res0x.canonicalHash).toBe(validCanonical);

      // Invalid permit hashes
      const resEmpty = validatePermitHash('');
      expect(resEmpty.isValid).toBe(false);

      const resShort = validatePermitHash('abc123');
      expect(resShort.isValid).toBe(false);
      expect(resShort.errorMessage).toContain('expected 64 hex characters');

      const resNonHex = validatePermitHash(
        'zzzz222233334444555566667777888899990000aaaabbbbccccddddeeeeffff',
      );
      expect(resNonHex.isValid).toBe(false);
    });

    it('displays validation alert in UI when invalid permit hash is passed', () => {
      const html = renderToString(
        <WarningApproval
          context={{
            permitHash: 'invalid-hash-too-short',
            vaultAccountId: 'vault.testnet',
            receiverAccountId: 'target.testnet',
            amountNear: '1.0',
            reasonCodes: ['RECENT_DEPLOYMENT'],
          }}
        />,
      );

      expect(html).toContain('Validation Error');
      expect(html).toContain('expected 64 hex characters');
      expect(html).toContain('&lt;invalid_permit_hash&gt;');
    });
  });

  describe('4. Interactive Form Inputs & Test ID Attributes', () => {
    it('renders all required form input fields with proper test IDs for automated E2E testing', () => {
      const html = renderToString(<WarningApproval />);

      expect(html).toContain('data-testid="vault-account-input"');
      expect(html).toContain('data-testid="owner-account-input"');
      expect(html).toContain('data-testid="network-select"');
      expect(html).toContain('data-testid="permit-hash-input"');
      expect(html).toContain('data-testid="copy-cli-command-btn"');
      expect(html).toContain('data-testid="simulate-approval-btn"');
    });

    it('renders all three network options in network-select', () => {
      const html = renderToString(<WarningApproval />);

      expect(html).toContain('value="testnet"');
      expect(html).toContain('value="mainnet"');
      expect(html).toContain('value="sandbox"');
      expect(html).toContain('testnet');
      expect(html).toContain('mainnet');
      expect(html).toContain('sandbox');
    });
  });

  describe('5. Adversarial Input Neutralization (XSS Resistance)', () => {
    it('safely escapes script tags and adversarial payloads in context fields', () => {
      const maliciousPayloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert(1)>',
        '"><svg onload=alert(document.domain)>',
        "'; DROP TABLE reports; --",
      ];

      for (const payload of maliciousPayloads) {
        const html = renderToString(
          <WarningApproval
            context={{
              permitHash: '7a8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
              vaultAccountId: 'vault.testnet',
              receiverAccountId: payload,
              amountNear: '0.05',
              reasonCodes: [payload],
            }}
          />,
        );

        expect(html).not.toContain('<script>');
        expect(html).not.toContain('<img src=x');
        expect(html).not.toContain('<svg onload');
      }
    });
  });
});
