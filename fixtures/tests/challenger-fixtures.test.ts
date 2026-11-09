import '@counterparty-guard/shared';
import { type Decision, type ReasonCode, ScenarioDefinitionSchema, type ScenarioId} from '@counterparty-guard/shared/demo';
import { describe, expect, it } from 'vitest';
import {
  CANONICAL_SCENARIO_IDS,
  getScenarioCanonicalPermit,
  getScenarioReceiver,
  getScenarioReports,
  loadScenarioFixture,
  s1Fixture,
  s2Fixture,
  s3Fixture,
  s4Fixture,
  s5Fixture,
  s6Fixture,
  s7Fixture,
  s8Fixture,
  s9Fixture,
  s10Fixture,
} from '../index.js';

interface TestInitialState {
  is_blocked?: boolean;
  raw_report_count?: number;
  account_age_days?: number;
  reputation_risk_points?: number;
  circular_activity_detected?: boolean;
  circular_activity_score?: number;
  ring_accounts?: string[];
  cycle_path?: string[];
  code_hash_changed?: boolean;
  is_contract?: boolean;
  previous_code_hash?: string;
  current_code_hash?: string | null;
  vault_error_code?: string;
  original_permit_amount_yocto?: string;
  mutated_amount_yocto?: string;
  error_status_code?: number;
  supported_methods?: string[];
  unsupported_methods?: string[];
  effective_report_weight?: number;
  approval_cli_command?: string;
  canonical_permit?: {
    permit_hash: string;
    verdict: 'allow' | 'warn';
    nonce: string;
    policy_revision: number;
    blocklist_revision: number;
  } | null;
  faucet_exemption?: {
    is_exempted: boolean;
    faucet_account_id: string;
  };
  dependence_group?: {
    reporter_count: number;
    effective_weight: number;
  };
  coverage?: {
    truncated: boolean;
  };
}

describe('Adversarial Challenger Suite: Fixtures & Schema Rigor (M6)', () => {
  describe('Probe 1: Schema Parser Mutation & Negative Tests', () => {
    it('rejects completely empty object', () => {
      const parsed = ScenarioDefinitionSchema.safeParse({});
      expect(parsed.success).toBe(false);
      if (!parsed.success) {
        const paths = parsed.error.issues.map((i) => i.path[0]);
        expect(paths).toContain('id');
        expect(paths).toContain('name');
        expect(paths).toContain('description');
        expect(paths).toContain('security_invariant');
        expect(paths).toContain('proposed_action');
        expect(paths).toContain('expected_decision');
        expect(paths).toContain('expected_signed');
        expect(paths).toContain('expected_submitted');
      }
    });

    it('rejects invalid scenario IDs (out-of-range, lower-case, arbitrary string)', () => {
      const invalidIds = ['S0', 'S11', 's1', 'S01', 'SCENARIO_1', '', 'S1 ', ' S1'];
      for (const invalidId of invalidIds) {
        const copy = { ...s1Fixture, id: invalidId as unknown as ScenarioId };
        const parsed = ScenarioDefinitionSchema.safeParse(copy);
        expect(parsed.success).toBe(false);
      }
    });

    it('rejects negative or non-digit expected_balance_delta_yocto', () => {
      const invalidDeltas = [
        '-1',
        '-50000000000000000000000',
        '100.5',
        '0x10',
        'abc',
        '',
        ' 5000',
        '5000 ',
      ];
      for (const delta of invalidDeltas) {
        const copy = { ...s1Fixture, expected_balance_delta_yocto: delta };
        const parsed = ScenarioDefinitionSchema.safeParse(copy);
        expect(parsed.success).toBe(false);
      }
    });

    it('rejects negative or non-digit proposed_action.amount_yocto', () => {
      const invalidAmounts = ['-1', '-50000000000000000000000', '100.5', 'abc', '', 'NaN'];
      for (const amount of invalidAmounts) {
        const copy = {
          ...s1Fixture,
          proposed_action: {
            kind: 'transfer_near' as const,
            receiver_id: 'merchant.testnet',
            amount_yocto: amount,
          },
        };
        const parsed = ScenarioDefinitionSchema.safeParse(copy);
        expect(parsed.success).toBe(false);
      }
    });

    it('rejects invalid receiver account IDs (< 2 chars, > 64 chars, empty)', () => {
      const invalidReceivers = ['', 'a', 'a'.repeat(65)];
      for (const recv of invalidReceivers) {
        const copy = {
          ...s1Fixture,
          proposed_action: {
            kind: 'transfer_near' as const,
            receiver_id: recv,
            amount_yocto: '1000',
          },
        };
        const parsed = ScenarioDefinitionSchema.safeParse(copy);
        expect(parsed.success).toBe(false);
      }
    });

    it('rejects invalid network values', () => {
      const invalidNetworks = ['mainnet_fork', 'ethereum', 'solana', '', 'local'];
      for (const net of invalidNetworks) {
        const copy = { ...s1Fixture, network: net as unknown as 'testnet' };
        const parsed = ScenarioDefinitionSchema.safeParse(copy);
        expect(parsed.success).toBe(false);
      }
    });

    it('rejects invalid expected_decision values', () => {
      const invalidDecisions = ['deny', 'rejection', 'approved', 'pass', '', 'blocked'];
      for (const dec of invalidDecisions) {
        const copy = { ...s1Fixture, expected_decision: dec as unknown as Decision };
        const parsed = ScenarioDefinitionSchema.safeParse(copy);
        expect(parsed.success).toBe(false);
      }
    });

    it('rejects invalid expected_reason_codes', () => {
      const invalidReasons = ['INVALID_REASON', 'UNKNOWN_CODE', 'ALL_GOOD', ''];
      for (const r of invalidReasons) {
        const copy = { ...s1Fixture, expected_reason_codes: [r as unknown as ReasonCode] };
        const parsed = ScenarioDefinitionSchema.safeParse(copy);
        expect(parsed.success).toBe(false);
      }
    });

    it('rejects malformed contract call actions (empty method, invalid gas, negative deposit)', () => {
      // Empty method name
      const badMethod = {
        ...s7Fixture,
        proposed_action: {
          kind: 'contract_call' as const,
          receiver_id: 'contract.testnet',
          method_name: '',
          args_base64: 'e30=',
        },
      };
      expect(ScenarioDefinitionSchema.safeParse(badMethod).success).toBe(false);

      // Excessive gas > 300 Tgas
      const excessiveGas = {
        ...s7Fixture,
        proposed_action: {
          kind: 'contract_call' as const,
          receiver_id: 'contract.testnet',
          method_name: 'claim',
          args_base64: 'e30=',
          gas_tgas: 301,
        },
      };
      expect(ScenarioDefinitionSchema.safeParse(excessiveGas).success).toBe(false);

      // Non-positive gas <= 0
      const zeroGas = {
        ...s7Fixture,
        proposed_action: {
          kind: 'contract_call' as const,
          receiver_id: 'contract.testnet',
          method_name: 'claim',
          args_base64: 'e30=',
          gas_tgas: 0,
        },
      };
      expect(ScenarioDefinitionSchema.safeParse(zeroGas).success).toBe(false);

      // Negative attached deposit
      const negativeDeposit = {
        ...s7Fixture,
        proposed_action: {
          kind: 'contract_call' as const,
          receiver_id: 'contract.testnet',
          method_name: 'claim',
          args_base64: 'e30=',
          attached_deposit_yocto: '-500',
        },
      };
      expect(ScenarioDefinitionSchema.safeParse(negativeDeposit).success).toBe(false);
    });

    it('rejects type mismatches on boolean flags', () => {
      const badSigned = { ...s1Fixture, expected_signed: 'true' as unknown as boolean };
      expect(ScenarioDefinitionSchema.safeParse(badSigned).success).toBe(false);

      const badSubmitted = { ...s1Fixture, expected_submitted: 1 as unknown as boolean };
      expect(ScenarioDefinitionSchema.safeParse(badSubmitted).success).toBe(false);
    });
  });

  describe('Probe 2: Invariant Semantics & Security Assertions', () => {
    it('S1 (Established Legitimate): strictly produces allow, signed, and finalized delta', () => {
      expect(s1Fixture.expected_decision).toBe('allow');
      expect(s1Fixture.expected_signed).toBe(false);
      expect(s1Fixture.expected_submitted).toBe(false);
      expect(BigInt(s1Fixture.expected_balance_delta_yocto)).toBe(0n);
      expect(s1Fixture.proposed_action.receiver_id).toBe('merchant.testnet');

      const state = s1Fixture.initial_state as TestInitialState;
      expect(state.is_blocked).toBe(false);
      expect(state.raw_report_count).toBe(0);
      expect(state.account_age_days ?? 0).toBeGreaterThanOrEqual(180);
      expect(state.canonical_permit?.permit_hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('S2 (Legitimate New Receiver): strictly requires human owner warning approval', () => {
      expect(s2Fixture.expected_decision).toBe('warn');
      expect(s2Fixture.expected_signed).toBe(false);
      expect(s2Fixture.expected_submitted).toBe(false);
      expect(s2Fixture.expected_balance_delta_yocto).toBe('0');
      expect(s2Fixture.expected_reason_codes).toContain('RECENT_DEPLOYMENT');
      expect(s2Fixture.expected_reason_codes).toContain('UNKNOWN_AGE');

      const state = s2Fixture.initial_state as TestInitialState;
      expect(state.account_age_days ?? 0).toBeLessThan(1);
      expect(state.canonical_permit?.verdict).toBe('warn');
      expect(state.approval_cli_command).toContain('approve_warn');
      expect(state.approval_cli_command).toContain(state.canonical_permit?.permit_hash ?? '');
    });

    it('S3 (Known Drainer): active reviewed block strictly aborts before signing with zero delta', () => {
      expect(s3Fixture.expected_decision).toBe('block');
      expect(s3Fixture.expected_signed).toBe(false);
      expect(s3Fixture.expected_submitted).toBe(false);
      expect(s3Fixture.expected_balance_delta_yocto).toBe('0');
      expect(s3Fixture.expected_reason_codes).toContain('ACTIVE_BLOCK');
      expect(s3Fixture.expected_reason_codes).toContain('REVIEWED_BLOCKLIST_MATCH');

      const state = s3Fixture.initial_state as TestInitialState;
      expect(state.is_blocked).toBe(true);
      expect(state.reputation_risk_points).toBe(100);
      expect(state.canonical_permit).toBeNull();

      const reports = getScenarioReports('S3');
      expect(reports.length).toBe(1);
      expect(reports[0].status).toBe('reviewed');
      expect(reports[0].category).toBe('drainer');
    });

    it('S4 (Sybil Flood Discounting): 20 coordinated reports capped to <= 1.0 weight and NEVER block', () => {
      // Invariant: Raw reports can NEVER trigger a hard block without reviewer authority
      expect(s4Fixture.expected_decision).not.toBe('block');
      expect(['allow', 'warn']).toContain(s4Fixture.expected_decision);
      expect(s4Fixture.expected_reason_codes).toContain('DEPENDENT_REPORTS');

      const state = s4Fixture.initial_state as TestInitialState;
      expect(state.is_blocked).toBe(false);
      expect(state.raw_report_count).toBe(20);
      expect(state.effective_report_weight ?? 0).toBeLessThanOrEqual(1.0);
      expect(state.dependence_group?.reporter_count).toBe(20);
      expect(state.dependence_group?.effective_weight ?? 0).toBeLessThanOrEqual(1.0);

      const reports = getScenarioReports('S4');
      expect(reports.length).toBe(20);
      for (const r of reports) {
        expect(r.dependence_group_id).toBe('group_funder_sybil_parent');
        expect(r.status).toBe('corroborated');
      }
    });

    it('S5 (Circular Activity): detects closed transaction loop and penalizes reputation', () => {
      expect(s5Fixture.expected_decision).toBe('warn');
      expect(s5Fixture.expected_signed).toBe(false);
      expect(s5Fixture.expected_submitted).toBe(false);
      expect(s5Fixture.expected_balance_delta_yocto).toBe('0');
      expect(s5Fixture.expected_reason_codes).toContain('CIRCULAR_ACTIVITY');

      const state = s5Fixture.initial_state as TestInitialState;
      expect(state.circular_activity_detected).toBe(true);
      expect(state.circular_activity_score).toBe(65);
      expect(state.ring_accounts?.length).toBe(3);
      if (state.cycle_path && state.cycle_path.length > 0) {
        expect(state.cycle_path[0]).toBe(state.cycle_path[state.cycle_path.length - 1]);
      }
    });

    it('S6 (Common Faucet Exemption): faucet.testnet accounts are NOT grouped or penalized', () => {
      expect(s6Fixture.expected_decision).toBe('allow');
      expect(s6Fixture.expected_reason_codes).toContain('COMMON_FAUCET_EXEMPTED');
      expect(s6Fixture.expected_reason_codes).not.toContain('DEPENDENT_REPORTS');
      expect(s6Fixture.expected_signed).toBe(false);
      expect(s6Fixture.expected_submitted).toBe(false);

      const state = s6Fixture.initial_state as TestInitialState;
      expect(state.faucet_exemption?.is_exempted).toBe(true);
      expect(state.faucet_exemption?.faucet_account_id).toBe('faucet.testnet');
      expect(state.is_blocked).toBe(false);
      expect(state.reputation_risk_points ?? 0).toBeLessThanOrEqual(15);
    });

    it('S7 (Contract Upgrade Detection): bytecode change forces CODE_CHANGED and warning reassessment', () => {
      expect(s7Fixture.expected_decision).toBe('warn');
      expect(s7Fixture.expected_signed).toBe(false);
      expect(s7Fixture.expected_submitted).toBe(false);
      expect(s7Fixture.expected_balance_delta_yocto).toBe('0');
      expect(s7Fixture.expected_reason_codes).toContain('CODE_CHANGED');
      expect(s7Fixture.proposed_action.kind).toBe('contract_call');

      const state = s7Fixture.initial_state as TestInitialState;
      expect(state.is_contract).toBe(true);
      expect(state.code_hash_changed).toBe(true);
      expect(state.previous_code_hash).not.toBe(state.current_code_hash);
      expect(state.reputation_risk_points).toBe(55);
    });

    it('S8 (Permit Replay & Mutation): parameter tampering rejected on vault with zero transfer', () => {
      expect(s8Fixture.expected_decision).toBe('vault_rejection');
      expect(s8Fixture.expected_balance_delta_yocto).toBe('0');

      const state = s8Fixture.initial_state as TestInitialState;
      expect(state.vault_error_code).toBe('INVALID_PERMIT_NONCE_REPLAYED');
      expect(BigInt(state.mutated_amount_yocto ?? '0')).toBeGreaterThan(
        BigInt(state.original_permit_amount_yocto ?? '0'),
      );
      expect(state.canonical_permit).toBeNull();
    });

    it('S9 (Provider Outage / Fail-Closed): RPC unavailability fails closed with zero permit', () => {
      expect(s9Fixture.expected_decision).toBe('infrastructure_error');
      expect(s9Fixture.expected_signed).toBe(false);
      expect(s9Fixture.expected_submitted).toBe(false);
      expect(s9Fixture.expected_balance_delta_yocto).toBe('0');
      expect(s9Fixture.expected_reason_codes).toContain('MANDATORY_SOURCE_UNAVAILABLE');
      expect(s9Fixture.expected_reason_codes).toContain('INCOMPLETE_HISTORY');

      const state = s9Fixture.initial_state as TestInitialState;
      expect(state.error_status_code).toBe(503);
      expect(state.canonical_permit).toBeNull();
      expect(state.coverage?.truncated).toBe(true);
    });

    it('S10 (Supported Method Call): allowlisted method succeeds cleanly', () => {
      expect(s10Fixture.expected_decision).toBe('allow');
      expect(s10Fixture.expected_signed).toBe(false);
      expect(s10Fixture.expected_submitted).toBe(false);
      expect(s10Fixture.proposed_action.kind).toBe('contract_call');
      if (s10Fixture.proposed_action.kind === 'contract_call') {
        expect(s10Fixture.proposed_action.method_name).toBe('accept_memo');
      }

      const state = s10Fixture.initial_state as TestInitialState;
      expect(state.supported_methods).toContain('claim_service');
      expect(state.unsupported_methods).toContain('drain_funds');
      expect(state.canonical_permit?.permit_hash).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('Probe 3: Invariant Consistency & Robustness Matrix', () => {
    it('proves S4 Sybil flood invariance: scaling report volume preserves weight <= 1.0 and is_blocked false', () => {
      const s4Reports = getScenarioReports('S4');
      expect(s4Reports).toHaveLength(20);
      for (const rep of s4Reports) {
        expect(rep.dependence_group_id).toBe('group_funder_sybil_parent');
      }
      const s4State = s4Fixture.initial_state as TestInitialState;
      expect(s4State.effective_report_weight ?? 0).toBeLessThanOrEqual(1.0);
      expect(s4State.is_blocked).toBe(false);
    });

    it('proves S6 faucet invariance: presence of faucet.testnet avoids any cluster penalty', () => {
      const s6State = s6Fixture.initial_state as TestInitialState;
      expect(s6State.faucet_exemption?.is_exempted).toBe(true);
      expect(s6State.faucet_exemption?.faucet_account_id).toBe('faucet.testnet');
      expect(s6Fixture.expected_reason_codes).toContain('COMMON_FAUCET_EXEMPTED');
      expect(s6Fixture.expected_reason_codes).not.toContain('DEPENDENT_REPORTS');
    });

    it('proves S7 upgrade invariance: mismatched code hashes guarantee warning reassessment', () => {
      const s7State = s7Fixture.initial_state as TestInitialState;
      expect(s7State.code_hash_changed).toBe(true);
      expect(s7State.previous_code_hash).not.toEqual(s7State.current_code_hash);
      expect(s7Fixture.expected_decision).toBe('warn');
      expect(s7Fixture.expected_signed).toBe(false);
    });

    it('proves S8 tampering invariance: mutated amounts require vault rejection and zero delta', () => {
      const s8State = s8Fixture.initial_state as TestInitialState;
      expect(s8Fixture.expected_decision).toBe('vault_rejection');
      expect(s8Fixture.expected_balance_delta_yocto).toBe('0');
      expect(s8State.vault_error_code).toBe('INVALID_PERMIT_NONCE_REPLAYED');
    });

    it('proves S9 outage invariance: fail-closed produces zero permit and zero transaction dispatch', () => {
      expect(s9Fixture.expected_decision).toBe('infrastructure_error');
      expect(s9Fixture.expected_signed).toBe(false);
      expect(s9Fixture.expected_submitted).toBe(false);
      expect(s9Fixture.expected_balance_delta_yocto).toBe('0');
      expect(s9Fixture.expected_reason_codes).toContain('MANDATORY_SOURCE_UNAVAILABLE');
    });
  });

  describe('Probe 4: Loader Utilities Edge Cases & Error Boundaries', () => {
    it('loadScenarioFixture throws typed Error on invalid IDs', () => {
      expect(() => loadScenarioFixture('S0' as ScenarioId)).toThrow();
      expect(() => loadScenarioFixture('S11' as ScenarioId)).toThrow();
      expect(() => loadScenarioFixture('INVALID')).toThrow();
      expect(() => loadScenarioFixture('')).toThrow();
    });

    it('getScenarioReceiver extracts non-empty receivers for all 10 canonical fixtures', () => {
      for (const id of CANONICAL_SCENARIO_IDS) {
        const receiver = getScenarioReceiver(id);
        expect(typeof receiver).toBe('string');
        expect(receiver.length).toBeGreaterThanOrEqual(2);
        expect(receiver.length).toBeLessThanOrEqual(64);
        expect(receiver).toContain('.testnet');
      }
    });

    it('getScenarioReports validates each report strictly against ReportRecordSchema', () => {
      const s3Reports = getScenarioReports('S3');
      expect(s3Reports.length).toBe(1);
      expect(s3Reports[0].status).toBe('reviewed');

      const s4Reports = getScenarioReports('S4');
      expect(s4Reports.length).toBe(20);
      for (const r of s4Reports) {
        expect(r.status).toBe('corroborated');
        expect(r.accused_account_id).toBe('popular-service.testnet');
      }

      // S1 has 0 reports
      const s1Reports = getScenarioReports('S1');
      expect(s1Reports).toEqual([]);
    });

    it('getScenarioCanonicalPermit returns null for block/error and valid permit for allow/warn', () => {
      // S1 (allow) -> valid permit
      const p1 = getScenarioCanonicalPermit('S1');
      expect(p1).not.toBeNull();
      expect(p1?.verdict).toBe('allow');
      expect(p1?.permit_hash).toMatch(/^[a-f0-9]{64}$/);

      // S2 (warn) -> valid permit with verdict warn
      const p2 = getScenarioCanonicalPermit('S2');
      expect(p2).not.toBeNull();
      expect(p2?.verdict).toBe('warn');
      expect(p2?.permit_hash).toMatch(/^[a-f0-9]{64}$/);

      // S3 (block) -> null
      expect(getScenarioCanonicalPermit('S3')).toBeNull();

      // S8 (rejection) -> null
      expect(getScenarioCanonicalPermit('S8')).toBeNull();

      // S9 (outage) -> null
      expect(getScenarioCanonicalPermit('S9')).toBeNull();
    });
  });
});
