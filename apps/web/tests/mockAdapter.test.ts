import { CheckResponseSchema, ExecutionPermitSchema, type ScenarioId } from '@counterparty-guard/shared/demo';
import { describe, expect, it } from 'vitest';
import {
  formatDisplayPermitHash,
  is0xPermitHash,
  isCanonicalPermitHash,
  mockAdapter,
  nearToYocto,
  normalizePermitHash,
  toCanonicalAction,
  toCanonicalCheckRequest,
} from '../src/adapters/mockAdapter';

describe('FixtureMockAdapter and Helpers (apps/web)', () => {
  describe('Permit Hash Normalization & Formatting', () => {
    const raw64 = '7a8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b';
    const prefixed66 = '0x7a8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b';
    const upper66 = '0x7A8B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B';

    it('correctly normalizes 0x-prefixed, uppercase, and untrimmed hashes', () => {
      expect(normalizePermitHash(raw64)).toBe(raw64);
      expect(normalizePermitHash(prefixed66)).toBe(raw64);
      expect(normalizePermitHash(upper66)).toBe(raw64);
      expect(normalizePermitHash(`  ${prefixed66}  `)).toBe(raw64);
    });

    it('validates canonical and 0x formats with typeguards', () => {
      expect(isCanonicalPermitHash(raw64)).toBe(true);
      expect(isCanonicalPermitHash(prefixed66)).toBe(false);

      expect(is0xPermitHash(prefixed66)).toBe(true);
      expect(is0xPermitHash(upper66)).toBe(true);
      expect(is0xPermitHash(raw64)).toBe(false);
    });

    it('rejects invalid permit hash lengths and non-hex characters', () => {
      expect(() => normalizePermitHash(`0x${'a'.repeat(63)}`)).toThrow(
        /expected 64 hex characters/,
      );
      expect(() => normalizePermitHash(`0x${'a'.repeat(65)}`)).toThrow(
        /expected 64 hex characters/,
      );
      expect(() => normalizePermitHash(`0x${'z'.repeat(64)}`)).toThrow(
        /expected 64 hex characters/,
      );
      expect(() => normalizePermitHash('')).toThrow(/must be a non-empty string/);
    });

    it('formats display hashes with prefix and truncation', () => {
      expect(formatDisplayPermitHash(raw64)).toBe(prefixed66);
      expect(formatDisplayPermitHash(raw64, { prefix0x: false })).toBe(raw64);
      expect(formatDisplayPermitHash(raw64, { truncate: true })).toBe('0x7a8b1c...8f9a0b');
      expect(formatDisplayPermitHash(raw64, { truncate: true, startChars: 4, endChars: 4 })).toBe(
        '0x7a8b...9a0b',
      );
      expect(formatDisplayPermitHash(null)).toBe('None');
      expect(formatDisplayPermitHash(undefined)).toBe('None');
    });
  });

  describe('Lossless NEAR Conversion (nearToYocto)', () => {
    it('converts common NEAR values with exact integer precision', () => {
      expect(nearToYocto('0.05')).toBe('50000000000000000000000');
      expect(nearToYocto('1')).toBe('1000000000000000000000000');
      expect(nearToYocto('1.0')).toBe('1000000000000000000000000');
      expect(nearToYocto('0.000000000000000000000001')).toBe('1');
      expect(nearToYocto('0')).toBe('0');
    });

    it('throws on non-numeric or malformed amount inputs', () => {
      expect(() => nearToYocto('abc')).toThrow(/Invalid NEAR amount format/);
      expect(() => nearToYocto('-1.5')).toThrow(/Invalid NEAR amount format/);
    });
  });

  describe('Canonical Action and CheckRequest Construction', () => {
    it('maps transfer_near action params correctly', () => {
      const action = toCanonicalAction({
        vaultAccountId: 'vault.testnet',
        receiverAccountId: 'merchant.testnet',
        actionKind: 'transfer_near',
        amountNear: '0.05',
      });
      expect(action.kind).toBe('transfer_near');
      if (action.kind === 'transfer_near') {
        expect(action.receiver_id).toBe('merchant.testnet');
        expect(action.amount_yocto).toBe('50000000000000000000000');
      }
    });

    it('maps contract_call action params with base64 encoded arguments', () => {
      const action = toCanonicalAction({
        vaultAccountId: 'vault.testnet',
        receiverAccountId: 'contract.testnet',
        actionKind: 'contract_call',
        amountNear: '0.05',
        methodName: 'claim_reward',
        argsJson: '{"id":101}',
      });
      expect(action.kind).toBe('contract_call');
      if (action.kind === 'contract_call') {
        expect(action.receiver_id).toBe('contract.testnet');
        expect(action.method_name).toBe('claim_reward');
        expect(Buffer.from(action.args_base64, 'base64').toString('utf-8')).toBe('{"id":101}');
      }
    });

    it('generates a valid CheckRequest conforming to schema', () => {
      const req = toCanonicalCheckRequest(
        {
          network: 'testnet',
          vaultAccountId: 'vault.testnet',
          receiverAccountId: 'merchant.testnet',
          actionKind: 'transfer_near',
          amountNear: '0.05',
        },
        'req-12345',
      );
      expect(req.schema_version).toBe(1);
      expect(req.vault_id).toBe('vault.testnet');
      expect(req.request_id).toBe('req-12345');
    });
  });

  describe('Scenario S1–S10 Evaluations', () => {
    const scenarios: Array<{
      id: ScenarioId;
      expectedDecision: 'allow' | 'warn' | 'block' | 'error';
      hasPermit: boolean;
      expectedCanonicalDecision: 'allow' | 'warn' | 'block';
    }> = [
      { id: 'S1', expectedDecision: 'allow', hasPermit: false, expectedCanonicalDecision: 'allow' },
      { id: 'S2', expectedDecision: 'warn', hasPermit: false, expectedCanonicalDecision: 'warn' },
      { id: 'S3', expectedDecision: 'block', hasPermit: false, expectedCanonicalDecision: 'block' },
      { id: 'S4', expectedDecision: 'allow', hasPermit: false, expectedCanonicalDecision: 'allow' },
      { id: 'S5', expectedDecision: 'warn', hasPermit: false, expectedCanonicalDecision: 'warn' },
      { id: 'S6', expectedDecision: 'allow', hasPermit: false, expectedCanonicalDecision: 'allow' },
      { id: 'S7', expectedDecision: 'warn', hasPermit: false, expectedCanonicalDecision: 'warn' },
      { id: 'S8', expectedDecision: 'error', hasPermit: false, expectedCanonicalDecision: 'block' },
      { id: 'S9', expectedDecision: 'error', hasPermit: false, expectedCanonicalDecision: 'block' },
      { id: 'S10', expectedDecision: 'allow', hasPermit: false, expectedCanonicalDecision: 'allow' },
    ];

    for (const { id, expectedDecision, hasPermit, expectedCanonicalDecision } of scenarios) {
      it(`evaluates ${id} matching specifications and passing schemas`, () => {
        const result = mockAdapter.evaluateScenario(id);

        expect(result.matchedScenarioId).toBe(id);
        expect(result.verdict.decision).toBe(expectedDecision);
        expect(result.canonicalResponse.decision).toBe(expectedCanonicalDecision);

        // CheckResponseSchema verification
        const parsedResponse = CheckResponseSchema.safeParse(result.canonicalResponse);
        expect(parsedResponse.success).toBe(true);

        if (hasPermit) {
          expect(result.permit).toBeNull();
          expect(result.permit?.canonical).not.toBeNull();
          expect(result.permit?.canonicalHash).toMatch(/^[a-f0-9]{64}$/);
          expect(result.permit?.displayHash).toMatch(/^0x[a-f0-9]{64}$/);

          // ExecutionPermitSchema verification
          const parsedPermit = ExecutionPermitSchema.safeParse(result.permit?.canonical);
          expect(parsedPermit.success).toBe(true);
        } else {
          expect(result.permit).toBeNull();
          expect(result.canonicalResponse.permit).toBeNull();
        }
      });
    }
  });

  describe('Dynamic Heuristic Evaluation for Custom Inputs', () => {
    it('blocks malicious keyword targets with ACTIVE_BLOCK', () => {
      const result = mockAdapter.evaluate({
        vaultAccountId: 'vault.agent-c.testnet',
        receiverAccountId: 'exploit-drainer.testnet',
        actionKind: 'transfer_near',
        amountNear: '0.05',
      });
      expect(result.verdict.decision).toBe('block');
      expect(result.verdict.riskScore).toBe(100);
      expect(result.verdict.reasonCodes).toContain('ACTIVE_BLOCK');
      expect(result.permit).toBeNull();
      expect(result.isCustomEvaluation).toBe(true);
    });

    it('warns on excessive transfer amounts with POLICY_LIMIT_EXCEEDED', () => {
      const result = mockAdapter.evaluate({
        vaultAccountId: 'vault.agent-c.testnet',
        receiverAccountId: 'friend.testnet',
        actionKind: 'transfer_near',
        amountNear: '50.0',
      });
      expect(result.verdict.decision).toBe('warn');
      expect(result.verdict.riskScore).toBe(80);
      expect(result.verdict.reasonCodes).toContain('POLICY_LIMIT_EXCEEDED');
      expect(result.permit).toBeNull();
      expect(result.isCustomEvaluation).toBe(true);
    });

    it('warns on sensitive contract calls', () => {
      const result = mockAdapter.evaluate({
        vaultAccountId: 'vault.agent-c.testnet',
        receiverAccountId: 'custom-contract.testnet',
        actionKind: 'contract_call',
        amountNear: '0.01',
        methodName: 'upgrade',
        argsJson: '{}',
      });
      expect(result.verdict.decision).toBe('warn');
      expect(result.verdict.reasonCodes).toContain('CODE_CHANGED');
    });

    it('resolves preset scenario when parameters match preset receiver and amount', () => {
      const result = mockAdapter.evaluate({
        vaultAccountId: 'vault.agent-c.testnet',
        receiverAccountId: 'known-drainer.testnet',
        actionKind: 'transfer_near',
        amountNear: '0.05',
      });
      expect(result.matchedScenarioId).toBe('S3');
      expect(result.verdict.decision).toBe('block');
      expect(result.isCustomEvaluation).toBe(false);
    });
  });
});
