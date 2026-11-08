import {
  ActionSchema,
  CheckRequestSchema,
  CheckResponseSchema,
  ExecutionPermitSchema,
  ReasonCodeSchema,
  type ScenarioId,
} from '@counterparty-guard/shared';
import { describe, expect, it } from 'vitest';
import {
  type ActionParams,
  FixtureMockAdapter,
  evaluateAction,
  evaluateScenario,
  formatDisplayPermitHash,
  is0xPermitHash,
  isCanonicalPermitHash,
  mockAdapter,
  nearToYocto,
  normalizePermitHash,
  toCanonicalAction,
  toCanonicalCheckRequest,
} from '../src/adapters/mockAdapter';

describe('Adversarial Boundary Value Analysis & Edge Case Suite (challenger_m2_1_rep)', () => {
  describe('1. Boundary NEAR Amount Inputs & Lossless Arithmetic', () => {
    it('handles zero amounts in various string representations', () => {
      const zeroVariants = ['0', '0.0', '0.000000', '0.000000000000000000000000'];
      for (const zero of zeroVariants) {
        expect(nearToYocto(zero)).toBe('0');

        const action = toCanonicalAction({
          vaultAccountId: 'vault.testnet',
          receiverAccountId: 'new-vendor.testnet',
          actionKind: 'transfer_near',
          amountNear: zero,
        });
        expect(action.kind).toBe('transfer_near');
        if (action.kind === 'transfer_near') {
          expect(action.amount_yocto).toBe('0');
        }

        const evalRes = evaluateAction({
          vaultAccountId: 'vault.testnet',
          receiverAccountId: 'new-vendor.testnet',
          actionKind: 'transfer_near',
          amountNear: zero,
        });
        expect(CheckResponseSchema.safeParse(evalRes.canonicalResponse).success).toBe(true);
        expect(evalRes.matchedScenarioId).toBe('S2');
      }
    });

    it('handles exact 1 yoctoNEAR (smallest non-zero unit on NEAR: 10^-24)', () => {
      const oneYoctoNear = '0.000000000000000000000001';
      expect(nearToYocto(oneYoctoNear)).toBe('1');

      const action = toCanonicalAction({
        vaultAccountId: 'vault.testnet',
        receiverAccountId: 'merchant.testnet',
        actionKind: 'transfer_near',
        amountNear: oneYoctoNear,
      });
      if (action.kind === 'transfer_near') {
        expect(action.amount_yocto).toBe('1');
      }
    });

    it('truncates sub-yocto precision beyond 24 decimal places safely', () => {
      const subYocto = '0.00000000000000000000000099999';
      expect(nearToYocto(subYocto)).toBe('0');

      const onePlusSubYocto = '0.00000000000000000000000199999';
      expect(nearToYocto(onePlusSubYocto)).toBe('1');
    });

    it('handles standard transaction amounts (0.05, 1.0, 5.0, 10.0)', () => {
      expect(nearToYocto('0.05')).toBe('50000000000000000000000');
      expect(nearToYocto('1.0')).toBe('1000000000000000000000000');
      expect(nearToYocto('5.0')).toBe('5000000000000000000000000');
      expect(nearToYocto('10.0')).toBe('10000000000000000000000000');
    });

    it('handles boundary amounts around the 10.0 NEAR policy limit threshold', () => {
      // 9.99 NEAR -> below threshold (warn UNKNOWN_AGE, not POLICY_LIMIT_EXCEEDED)
      const below = evaluateAction({
        vaultAccountId: 'vault.testnet',
        receiverAccountId: 'unknown-vendor.testnet',
        actionKind: 'transfer_near',
        amountNear: '9.99',
      });
      expect(below.verdict.decision).toBe('warn');
      expect(below.verdict.reasonCodes).toContain('UNKNOWN_AGE');
      expect(below.verdict.reasonCodes).not.toContain('POLICY_LIMIT_EXCEEDED');

      // 10.00 NEAR -> exactly on boundary
      const exact = evaluateAction({
        vaultAccountId: 'vault.testnet',
        receiverAccountId: 'unknown-vendor.testnet',
        actionKind: 'transfer_near',
        amountNear: '10.00',
      });
      expect(exact.verdict.decision).toBe('warn');
      expect(exact.verdict.reasonCodes).toContain('UNKNOWN_AGE');
      expect(exact.verdict.reasonCodes).not.toContain('POLICY_LIMIT_EXCEEDED');

      // 10.01 NEAR -> strictly above threshold
      const above = evaluateAction({
        vaultAccountId: 'vault.testnet',
        receiverAccountId: 'unknown-vendor.testnet',
        actionKind: 'transfer_near',
        amountNear: '10.01',
      });
      expect(above.verdict.decision).toBe('warn');
      expect(above.verdict.riskScore).toBe(80);
      expect(above.verdict.reasonCodes).toContain('POLICY_LIMIT_EXCEEDED');
    });

    it('handles astronomical/extremely large amounts without arithmetic overflow', () => {
      // 100 million NEAR
      const hundredMillion = '100000000';
      expect(nearToYocto(hundredMillion)).toBe('100000000000000000000000000000000');

      // Total supply boundary: 1 billion NEAR
      const oneBillion = '1000000000';
      expect(nearToYocto(oneBillion)).toBe('1000000000000000000000000000000000');

      // 10^30 NEAR (surpasses Number.MAX_SAFE_INTEGER in yocto by many orders of magnitude)
      const hugeNear = '1000000000000000000000000000000';
      const hugeYocto = nearToYocto(hugeNear);
      expect(hugeYocto).toBe('1000000000000000000000000000000000000000000000000000000');

      const evalRes = evaluateAction({
        vaultAccountId: 'vault.testnet',
        receiverAccountId: 'vendor.testnet',
        actionKind: 'transfer_near',
        amountNear: hugeNear,
      });
      expect(evalRes.verdict.decision).toBe('warn');
      expect(evalRes.verdict.reasonCodes).toContain('POLICY_LIMIT_EXCEEDED');
      expect(CheckResponseSchema.safeParse(evalRes.canonicalResponse).success).toBe(true);
    });

    it('handles leading zeros and formatted decimal points', () => {
      expect(nearToYocto('0005.5000')).toBe('5500000000000000000000000');
      expect(nearToYocto('00000.1')).toBe('100000000000000000000000');
    });

    it('rejects negative, scientific notation, and non-numeric amounts in nearToYocto', () => {
      const invalidInputs = [
        '-1',
        '-0.05',
        '1e5',
        '1e-24',
        'NaN',
        'Infinity',
        '-Infinity',
        '1,000.00',
        '.5',
        '5.',
        'abc',
        '',
        '   ',
        '1.2.3',
      ];
      for (const invalid of invalidInputs) {
        expect(() => nearToYocto(invalid)).toThrow(/Invalid NEAR amount format/);
      }
    });

    it('defaults empty or undefined amount to 0 in toCanonicalAction', () => {
      const action = toCanonicalAction({
        vaultAccountId: 'vault.testnet',
        receiverAccountId: 'vendor.testnet',
        actionKind: 'transfer_near',
        amountNear: '',
      });
      if (action.kind === 'transfer_near') {
        expect(action.amount_yocto).toBe('0');
      }
    });
  });

  describe('2. Contract Call Argument Strings & Encoding', () => {
    it('handles valid simple and nested JSON payloads with accurate base64 round-trip', () => {
      const validPayloads = [
        '{}',
        '{"id": 42}',
        '{"user": {"name": "alice", "roles": ["admin", "auditor"]}, "active": true, "score": 98.6}',
        '{"tokens": [1, 2, 3, 4], "nested": {"a": {"b": {"c": null}}}}',
        '[]',
        '[{"tx": 1}, {"tx": 2}]',
      ];

      for (const jsonStr of validPayloads) {
        const action = toCanonicalAction({
          vaultAccountId: 'vault.testnet',
          receiverAccountId: 'contract.testnet',
          actionKind: 'contract_call',
          amountNear: '0.01',
          methodName: 'execute_action',
          argsJson: jsonStr,
        });

        expect(action.kind).toBe('contract_call');
        if (action.kind === 'contract_call') {
          const decoded = Buffer.from(action.args_base64, 'base64').toString('utf-8');
          expect(decoded).toBe(jsonStr);
          expect(action.method_name).toBe('execute_action');
          expect(action.gas_tgas).toBe(30);
          expect(ActionSchema.safeParse(action).success).toBe(true);
        }
      }
    });

    it('handles empty and whitespace argument strings with fallback to "{}"', () => {
      const emptyVariants = ['', '   ', '\t\n  ', undefined];
      for (const empty of emptyVariants) {
        const action = toCanonicalAction({
          vaultAccountId: 'vault.testnet',
          receiverAccountId: 'contract.testnet',
          actionKind: 'contract_call',
          amountNear: '0',
          methodName: 'ping',
          argsJson: empty,
        });

        if (action.kind === 'contract_call') {
          const decoded = Buffer.from(action.args_base64, 'base64').toString('utf-8');
          expect(decoded).toBe('{}');
          expect(ActionSchema.safeParse(action).success).toBe(true);
        }
      }
    });

    it('handles non-JSON or raw text strings safely without throwing', () => {
      const rawStrings = ['plain text parameter', '{ unquoted_key: 123 }', 'not a json'];
      for (const raw of rawStrings) {
        const action = toCanonicalAction({
          vaultAccountId: 'vault.testnet',
          receiverAccountId: 'contract.testnet',
          actionKind: 'contract_call',
          amountNear: '0',
          methodName: 'raw_call',
          argsJson: raw,
        });
        if (action.kind === 'contract_call') {
          const decoded = Buffer.from(action.args_base64, 'base64').toString('utf-8');
          expect(decoded).toBe(raw);
          expect(ActionSchema.safeParse(action).success).toBe(true);
        }
      }
    });

    it('handles large contract argument payloads (up to 50KB)', () => {
      const largeObj = {
        data: 'x'.repeat(40000),
        signatures: Array.from({ length: 50 }, (_, i) => `sig_${i}_${'a'.repeat(64)}`),
      };
      const largeJson = JSON.stringify(largeObj);

      const action = toCanonicalAction({
        vaultAccountId: 'vault.testnet',
        receiverAccountId: 'contract.testnet',
        actionKind: 'contract_call',
        amountNear: '0.1',
        methodName: 'batch_verify',
        argsJson: largeJson,
      });

      if (action.kind === 'contract_call') {
        const decoded = Buffer.from(action.args_base64, 'base64').toString('utf-8');
        expect(decoded).toBe(largeJson);
        expect(ActionSchema.safeParse(action).success).toBe(true);
      }
    });

    it('evaluates contract call action method sensitivity correctly', () => {
      const sensitiveMethods = ['transfer', 'set_owner', 'upgrade', 'execute'];
      for (const method of sensitiveMethods) {
        const res = evaluateAction({
          vaultAccountId: 'vault.testnet',
          receiverAccountId: 'custom-contract.testnet',
          actionKind: 'contract_call',
          amountNear: '0.01',
          methodName: method,
          argsJson: '{}',
        });
        expect(res.verdict.decision).toBe('warn');
        expect(res.verdict.reasonCodes).toContain('CODE_CHANGED');
        expect(res.verdict.reasonCodes).toContain('UNKNOWN_AGE');
        expect(CheckResponseSchema.safeParse(res.canonicalResponse).success).toBe(true);
      }

      const benignMethods = ['view_balance', 'get_stats', 'query_info', 'ping'];
      for (const method of benignMethods) {
        const res = evaluateAction({
          vaultAccountId: 'vault.testnet',
          receiverAccountId: 'custom-contract.testnet',
          actionKind: 'contract_call',
          amountNear: '0.01',
          methodName: method,
          argsJson: '{}',
        });
        expect(res.verdict.decision).toBe('allow');
        expect(res.verdict.riskScore).toBe(20);
        expect(CheckResponseSchema.safeParse(res.canonicalResponse).success).toBe(true);
      }
    });
  });

  describe('3. Permit Hash Formatting & Canonical Representations', () => {
    const canonicalHash = '7a8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b';
    const prefixed0x = `0x${canonicalHash}`;
    const prefixed0X = `0X${canonicalHash}`;
    const mixedCase = '7A8b1C2d3E4f5A6b7C8d9E0f1A2b3C4d5E6f7A8b9C0d1E2f3A4b5C6d7E8f9A0b';
    const prefixedMixedCase = `0x${mixedCase}`;

    it('normalizes all valid permit hash variants into lowercase canonical 64 hex', () => {
      expect(normalizePermitHash(canonicalHash)).toBe(canonicalHash);
      expect(normalizePermitHash(prefixed0x)).toBe(canonicalHash);
      expect(normalizePermitHash(prefixed0X)).toBe(canonicalHash);
      expect(normalizePermitHash(mixedCase)).toBe(canonicalHash);
      expect(normalizePermitHash(prefixedMixedCase)).toBe(canonicalHash);
      expect(normalizePermitHash(`   ${prefixed0x}   `)).toBe(canonicalHash);
      expect(normalizePermitHash(`\t${prefixedMixedCase}\n`)).toBe(canonicalHash);
    });

    it('validates canonical and 0x typeguards strictly', () => {
      expect(isCanonicalPermitHash(canonicalHash)).toBe(true);
      expect(isCanonicalPermitHash(prefixed0x)).toBe(false);
      expect(isCanonicalPermitHash(mixedCase)).toBe(false); // must be lowercase for canonical

      expect(is0xPermitHash(prefixed0x)).toBe(true);
      expect(is0xPermitHash(prefixed0X)).toBe(true);
      expect(is0xPermitHash(prefixedMixedCase)).toBe(true);
      expect(is0xPermitHash(canonicalHash)).toBe(false);
    });

    it('rejects malformed permit hashes with explicit errors', () => {
      // Length violations
      expect(() => normalizePermitHash('a'.repeat(63))).toThrow(/expected 64 hex characters/);
      expect(() => normalizePermitHash('a'.repeat(65))).toThrow(/expected 64 hex characters/);
      expect(() => normalizePermitHash(`0x${'a'.repeat(63)}`)).toThrow(
        /expected 64 hex characters/,
      );
      expect(() => normalizePermitHash(`0x${'a'.repeat(65)}`)).toThrow(
        /expected 64 hex characters/,
      );

      // Character violations
      expect(() => normalizePermitHash('g'.repeat(64))).toThrow(/expected 64 hex characters/);
      expect(() => normalizePermitHash('z'.repeat(64))).toThrow(/expected 64 hex characters/);
      expect(() => normalizePermitHash(`0x${'1234567890abcdef'.repeat(3)}ghij`)).toThrow(
        /expected 64 hex characters/,
      );

      // Empty and non-string inputs
      expect(() => normalizePermitHash('')).toThrow(/must be a non-empty string/);
      expect(() => normalizePermitHash('   ')).toThrow(/expected 64 hex characters/);
      // @ts-expect-error test non-string type
      expect(() => normalizePermitHash(null)).toThrow(/must be a non-empty string/);
      // @ts-expect-error test non-string type
      expect(() => normalizePermitHash(undefined)).toThrow(/must be a non-empty string/);
    });

    it('formats display hashes correctly for all option permutations', () => {
      // Default: 0x-prefixed full 66 chars
      expect(formatDisplayPermitHash(canonicalHash)).toBe(prefixed0x);
      expect(formatDisplayPermitHash(prefixed0x)).toBe(prefixed0x);

      // Without 0x prefix
      expect(formatDisplayPermitHash(canonicalHash, { prefix0x: false })).toBe(canonicalHash);
      expect(formatDisplayPermitHash(prefixed0x, { prefix0x: false })).toBe(canonicalHash);

      // Truncated with default (6 start, 6 end)
      expect(formatDisplayPermitHash(canonicalHash, { truncate: true })).toBe('0x7a8b1c...8f9a0b');
      expect(formatDisplayPermitHash(canonicalHash, { truncate: true, prefix0x: false })).toBe(
        '7a8b1c...8f9a0b',
      );

      // Custom truncation bounds
      expect(
        formatDisplayPermitHash(canonicalHash, { truncate: true, startChars: 8, endChars: 4 }),
      ).toBe('0x7a8b1c2d...9a0b');

      // Null, undefined, empty string handling
      expect(formatDisplayPermitHash(null)).toBe('None');
      expect(formatDisplayPermitHash(undefined)).toBe('None');
      expect(formatDisplayPermitHash('')).toBe('None');
    });

    it('verifies that permit generated by mockAdapter satisfies ExecutionPermitSchema', () => {
      const result = evaluateScenario('S1');
      expect(result.permit).not.toBeNull();
      const parsed = ExecutionPermitSchema.safeParse(result.permit?.canonical);
      expect(parsed.success).toBe(true);
      if (parsed.success) {
        expect(parsed.data.permit_hash).toMatch(/^[a-f0-9]{64}$/);
        expect(parsed.data.signature).toMatch(/^ed25519:[1-9A-HJ-NP-Za-km-z]{86,88}$/);
        expect(['allow', 'warn']).toContain(parsed.data.verdict);
        expect(parsed.data.expires_at).toBeGreaterThan(parsed.data.issued_at);
      }
    });
  });

  describe('4. Receiver Account ID Patterns & Scenario Matching', () => {
    it('matches exact canonical scenario receivers across cases and surrounding whitespace', () => {
      const matchCases: Array<{
        receiver: string;
        amount: string;
        expectedId: ScenarioId;
        expectedDecision: 'allow' | 'warn' | 'block' | 'error';
      }> = [
        {
          receiver: 'merchant.testnet',
          amount: '0.05',
          expectedId: 'S1',
          expectedDecision: 'allow',
        },
        {
          receiver: 'MERCHANT.TESTNET',
          amount: '0.05',
          expectedId: 'S1',
          expectedDecision: 'allow',
        },
        {
          receiver: '  merchant.testnet  ',
          amount: '0.05',
          expectedId: 'S1',
          expectedDecision: 'allow',
        },
        {
          receiver: 'merchant.testnet',
          amount: '5.0',
          expectedId: 'S8',
          expectedDecision: 'error',
        },
        {
          receiver: 'merchant.testnet',
          amount: '10.0',
          expectedId: 'S8',
          expectedDecision: 'error',
        },
        {
          receiver: 'new-vendor.testnet',
          amount: '0.05',
          expectedId: 'S2',
          expectedDecision: 'warn',
        },
        {
          receiver: 'NEW-VENDOR.TESTNET',
          amount: '0.05',
          expectedId: 'S2',
          expectedDecision: 'warn',
        },
        {
          receiver: 'known-drainer.testnet',
          amount: '0.05',
          expectedId: 'S3',
          expectedDecision: 'block',
        },
        {
          receiver: 'popular-service.testnet',
          amount: '0.05',
          expectedId: 'S4',
          expectedDecision: 'allow',
        },
        {
          receiver: 'wash-trader.testnet',
          amount: '0.05',
          expectedId: 'S5',
          expectedDecision: 'warn',
        },
        { receiver: 'user-b.testnet', amount: '0.05', expectedId: 'S6', expectedDecision: 'allow' },
        {
          receiver: 'contract.testnet',
          amount: '0.05',
          expectedId: 'S7',
          expectedDecision: 'warn',
        },
        {
          receiver: 'unknown-target.testnet',
          amount: '0.05',
          expectedId: 'S9',
          expectedDecision: 'error',
        },
        {
          receiver: 'fixture.testnet',
          amount: '0.01',
          expectedId: 'S10',
          expectedDecision: 'allow',
        },
      ];

      for (const { receiver, amount, expectedId, expectedDecision } of matchCases) {
        const res = evaluateAction({
          vaultAccountId: 'vault.agent-c.testnet',
          receiverAccountId: receiver,
          actionKind: 'transfer_near',
          amountNear: amount,
        });

        expect(res.matchedScenarioId).toBe(expectedId);
        expect(res.verdict.decision).toBe(expectedDecision);
        expect(res.isCustomEvaluation).toBe(false);
        expect(CheckResponseSchema.safeParse(res.canonicalResponse).success).toBe(true);
      }
    });

    it('evaluates malicious keywords in custom receiver IDs with active block', () => {
      const maliciousKeywords = ['drain', 'malicious', 'phish', 'exploit', 'scam'];
      for (const kw of maliciousKeywords) {
        const variations = [
          `prefix-${kw}.testnet`,
          `${kw}-suffix.testnet`,
          `sub.${kw}.near`,
          `${kw.toUpperCase()}.testnet`,
        ];

        for (const account of variations) {
          const res = evaluateAction({
            vaultAccountId: 'vault.agent-c.testnet',
            receiverAccountId: account,
            actionKind: 'transfer_near',
            amountNear: '0.05',
          });

          expect(res.verdict.decision).toBe('block');
          expect(res.verdict.riskScore).toBe(100);
          expect(res.verdict.reasonCodes).toContain('ACTIVE_BLOCK');
          expect(res.verdict.reasonCodes).toContain('REVIEWED_BLOCKLIST_MATCH');
          expect(res.permit).toBeNull();
          expect(res.canonicalResponse.decision).toBe('block');
          expect(CheckResponseSchema.safeParse(res.canonicalResponse).success).toBe(true);
        }
      }
    });

    it('enforces min and max account ID length in CheckRequestSchema validation', () => {
      // Length 1 -> should fail schema validation
      expect(() =>
        toCanonicalCheckRequest({
          vaultAccountId: 'vault.testnet',
          receiverAccountId: 'a',
          actionKind: 'transfer_near',
          amountNear: '1',
        }),
      ).toThrow();

      // Length 2 -> valid minimum NEAR account ID
      const minValid = toCanonicalCheckRequest({
        vaultAccountId: 'vault.testnet',
        receiverAccountId: 'ab',
        actionKind: 'transfer_near',
        amountNear: '1',
      });
      expect(minValid.action.receiver_id).toBe('ab');

      // Length 64 -> valid maximum NEAR account ID
      const maxValid = toCanonicalCheckRequest({
        vaultAccountId: 'vault.testnet',
        receiverAccountId: 'a'.repeat(64),
        actionKind: 'transfer_near',
        amountNear: '1',
      });
      expect(maxValid.action.receiver_id).toBe('a'.repeat(64));

      // Length 65 -> should fail schema validation
      expect(() =>
        toCanonicalCheckRequest({
          vaultAccountId: 'vault.testnet',
          receiverAccountId: 'a'.repeat(65),
          actionKind: 'transfer_near',
          amountNear: '1',
        }),
      ).toThrow();
    });

    it('documents behavior for NEAR implicit 64-hex accounts and top-level accounts', () => {
      // Implicit accounts (64 lowercase hex) without .testnet or .near suffix
      const implicitAccount = '98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6644cdf0dbd6de';
      const implicitRes = evaluateAction({
        vaultAccountId: 'vault.testnet',
        receiverAccountId: implicitAccount,
        actionKind: 'transfer_near',
        amountNear: '1.0',
      });

      // Characterizes custom action heuristic fallback
      expect(implicitRes.isCustomEvaluation).toBe(true);
      expect(CheckResponseSchema.safeParse(implicitRes.canonicalResponse).success).toBe(true);
      expect(implicitRes.verdict.decision).toBe('allow');

      // Suffix-matched account (.testnet or .near) triggers UNKNOWN_AGE
      const namedRes = evaluateAction({
        vaultAccountId: 'vault.testnet',
        receiverAccountId: 'random-unverified-vendor.testnet',
        actionKind: 'transfer_near',
        amountNear: '1.0',
      });
      expect(namedRes.verdict.decision).toBe('warn');
      expect(namedRes.verdict.reasonCodes).toContain('UNKNOWN_AGE');
    });
  });

  describe('5. Schema Compliance & Reason Code Invariant Verification', () => {
    it('guarantees all evaluateScenario outputs pass CheckResponseSchema', () => {
      const scenarioIds: ScenarioId[] = [
        'S1',
        'S2',
        'S3',
        'S4',
        'S5',
        'S6',
        'S7',
        'S8',
        'S9',
        'S10',
      ];
      for (const id of scenarioIds) {
        const result = evaluateScenario(id);
        const parseResult = CheckResponseSchema.safeParse(result.canonicalResponse);
        expect(parseResult.success).toBe(true);

        // Invariant: canonical response decision must NEVER be "error"
        expect(['allow', 'warn', 'block']).toContain(result.canonicalResponse.decision);

        // Invariant: all reason codes must be valid members of ReasonCodeSchema
        for (const code of result.verdict.reasonCodes) {
          expect(ReasonCodeSchema.safeParse(code).success).toBe(true);
        }
      }
    });

    it('guarantees custom evaluation permits have canonical 64 hex hashes and pass schema', () => {
      const customRes = evaluateAction({
        vaultAccountId: 'vault.agent-c.testnet',
        receiverAccountId: 'random-unknown.testnet',
        actionKind: 'transfer_near',
        amountNear: '0.5',
      });

      expect(customRes.permit).not.toBeNull();
      if (customRes.permit?.canonicalHash && customRes.permit?.displayHash) {
        expect(isCanonicalPermitHash(customRes.permit.canonicalHash)).toBe(true);
        expect(is0xPermitHash(customRes.permit.displayHash)).toBe(true);
      }
      const parsedPermit = ExecutionPermitSchema.safeParse(customRes.permit?.canonical);
      expect(parsedPermit.success).toBe(true);
    });

    it('verifies that blocked custom evaluations never issue permits', () => {
      const blockRes = evaluateAction({
        vaultAccountId: 'vault.agent-c.testnet',
        receiverAccountId: 'phishing-site.testnet',
        actionKind: 'transfer_near',
        amountNear: '0.05',
      });

      expect(blockRes.verdict.decision).toBe('block');
      expect(blockRes.permit).toBeNull();
      expect(blockRes.canonicalResponse.permit).toBeNull();
    });
  });
});
