import {
  ReasonCodeSchema,
  ReportRecordSchema,
  ScenarioDefinitionSchema,
  type ScenarioId,
  ScenarioIdSchema,
} from '@counterparty-guard/shared';
import { describe, expect, it } from 'vitest';
import {
  CANONICAL_SCENARIO_IDS,
  getAllScenarioFixtures,
  getScenarioCanonicalPermit,
  getScenarioExpectedDecision,
  getScenarioReceiver,
  getScenarioReports,
  listScenarioFixtures,
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

describe('Deterministic Fixtures S1–S10 & Loader (fixtures/index.ts)', () => {
  it('exports all 10 canonical scenario IDs', () => {
    expect(CANONICAL_SCENARIO_IDS).toEqual([
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
    ]);
  });

  describe('Tier 1: Canonical Scenario Schema Validation', () => {
    const scenarios = [
      { id: 'S1', fixture: s1Fixture },
      { id: 'S2', fixture: s2Fixture },
      { id: 'S3', fixture: s3Fixture },
      { id: 'S4', fixture: s4Fixture },
      { id: 'S5', fixture: s5Fixture },
      { id: 'S6', fixture: s6Fixture },
      { id: 'S7', fixture: s7Fixture },
      { id: 'S8', fixture: s8Fixture },
      { id: 'S9', fixture: s9Fixture },
      { id: 'S10', fixture: s10Fixture },
    ];

    for (const { id, fixture } of scenarios) {
      it(`Scenario ${id} strictly conforms to ScenarioDefinitionSchema`, () => {
        const parsed = ScenarioDefinitionSchema.safeParse(fixture);
        expect(parsed.success).toBe(true);
        expect(fixture.id).toBe(id);
        expect(fixture.name.length).toBeGreaterThan(5);
        expect(fixture.description.length).toBeGreaterThan(10);
        expect(fixture.security_invariant.length).toBeGreaterThan(10);
        expect(['testnet', 'mainnet', 'sandbox']).toContain(fixture.network);
      });
    }
  });

  describe('Tier 2: Scenario Invariants & Security Boundaries', () => {
    it('S1 (Established Legitimate): produces allow, finalized transfer, clean history', () => {
      expect(s1Fixture.expected_decision).toBe('allow');
      expect(s1Fixture.expected_reason_codes).toEqual([]);
      expect(s1Fixture.expected_signed).toBe(true);
      expect(s1Fixture.expected_submitted).toBe(true);
      expect(BigInt(s1Fixture.expected_balance_delta_yocto)).toBeGreaterThan(0n);
      expect(s1Fixture.proposed_action.receiver_id).toBe('merchant.testnet');

      const state = s1Fixture.initial_state as {
        is_blocked: boolean;
        raw_report_count: number;
        account_age_days: number;
      };
      expect(state.is_blocked).toBe(false);
      expect(state.raw_report_count).toBe(0);
      expect(state.account_age_days).toBeGreaterThanOrEqual(180);
    });

    it('S2 (Legitimate New): produces warn with RECENT_DEPLOYMENT & UNKNOWN_AGE, no auto signature', () => {
      expect(s2Fixture.expected_decision).toBe('warn');
      expect(s2Fixture.expected_reason_codes).toContain('RECENT_DEPLOYMENT');
      expect(s2Fixture.expected_reason_codes).toContain('UNKNOWN_AGE');
      expect(s2Fixture.expected_signed).toBe(false);
      expect(s2Fixture.expected_submitted).toBe(false);
      expect(s2Fixture.expected_balance_delta_yocto).toBe('0');
      expect(s2Fixture.proposed_action.receiver_id).toBe('new-vendor.testnet');

      const state = s2Fixture.initial_state as {
        account_age_days: number;
        approval_cli_command?: string;
      };
      expect(state.account_age_days).toBeLessThan(1);
      expect(state.approval_cli_command).toBeDefined();
      expect(state.approval_cli_command).toContain('approve_warn');
    });

    it('S3 (Reviewed Malicious): active block match triggers block, refused before signing', () => {
      expect(s3Fixture.expected_decision).toBe('block');
      expect(s3Fixture.expected_reason_codes).toContain('ACTIVE_BLOCK');
      expect(s3Fixture.expected_reason_codes).toContain('REVIEWED_BLOCKLIST_MATCH');
      expect(s3Fixture.expected_signed).toBe(false);
      expect(s3Fixture.expected_submitted).toBe(false);
      expect(s3Fixture.expected_balance_delta_yocto).toBe('0');
      expect(s3Fixture.proposed_action.receiver_id).toBe('known-drainer.testnet');

      const state = s3Fixture.initial_state as {
        is_blocked: boolean;
        blocklist_revision: number;
        reputation_risk_points: number;
      };
      expect(state.is_blocked).toBe(true);
      expect(state.blocklist_revision).toBeGreaterThan(0);
      expect(state.reputation_risk_points).toBe(100);

      const reports = getScenarioReports('S3');
      expect(reports.length).toBe(1);
      expect(reports[0].status).toBe('reviewed');
      expect(reports[0].category).toBe('drainer');
    });

    it('S4 (False-Report Flood): 20 Sybil reports discounted to 1.0 weight; NO hard block', () => {
      expect(['allow', 'warn']).toContain(s4Fixture.expected_decision);
      expect(s4Fixture.expected_decision).not.toBe('block');
      expect(s4Fixture.expected_reason_codes).toContain('DEPENDENT_REPORTS');
      expect(s4Fixture.proposed_action.receiver_id).toBe('popular-service.testnet');

      const state = s4Fixture.initial_state as {
        raw_report_count: number;
        effective_report_weight: number;
        is_blocked: boolean;
        dependence_group: { reporter_count: number; effective_weight: number };
      };
      // Absolute Reviewer Authority: raw unreviewed flood can NEVER cause is_blocked: true!
      expect(state.is_blocked).toBe(false);
      expect(state.raw_report_count).toBe(20);
      expect(state.effective_report_weight).toBe(1.0);
      expect(state.dependence_group.reporter_count).toBe(20);
      expect(state.dependence_group.effective_weight).toBe(1.0);

      const reports = getScenarioReports('S4');
      expect(reports.length).toBe(20);
      for (const r of reports) {
        expect(r.dependence_group_id).toBe('group_funder_sybil_parent');
      }
    });

    it('S5 (Circular Activity): 3-account ring detected, CIRCULAR_ACTIVITY, risk 65', () => {
      expect(s5Fixture.expected_decision).toBe('warn');
      expect(s5Fixture.expected_reason_codes).toContain('CIRCULAR_ACTIVITY');
      expect(s5Fixture.expected_signed).toBe(false);
      expect(s5Fixture.expected_submitted).toBe(false);
      expect(s5Fixture.proposed_action.receiver_id).toBe('wash-trader.testnet');

      const state = s5Fixture.initial_state as {
        circular_activity_detected: boolean;
        circular_activity_score: number;
        ring_accounts: string[];
      };
      expect(state.circular_activity_detected).toBe(true);
      expect(state.circular_activity_score).toBe(65);
      expect(state.ring_accounts.length).toBe(3);
    });

    it('S6 (Common Faucet): faucet.testnet funding exempted from Sybil clustering penalty', () => {
      expect(s6Fixture.expected_decision).toBe('allow');
      expect(s6Fixture.expected_reason_codes).toContain('COMMON_FAUCET_EXEMPTED');
      expect(s6Fixture.expected_reason_codes).not.toContain('DEPENDENT_REPORTS');
      expect(s6Fixture.proposed_action.receiver_id).toBe('user-b.testnet');

      const state = s6Fixture.initial_state as {
        faucet_exemption: { is_exempted: boolean; faucet_account_id: string };
      };
      expect(state.faucet_exemption.is_exempted).toBe(true);
      expect(state.faucet_exemption.faucet_account_id).toBe('faucet.testnet');
    });

    it('S7 (Upgraded Contract): code hash change triggers CODE_CHANGED and warning', () => {
      expect(s7Fixture.expected_decision).toBe('warn');
      expect(s7Fixture.expected_reason_codes).toContain('CODE_CHANGED');
      expect(s7Fixture.proposed_action.kind).toBe('contract_call');
      expect(s7Fixture.proposed_action.receiver_id).toBe('contract.testnet');

      const state = s7Fixture.initial_state as {
        is_contract: boolean;
        code_hash_changed: boolean;
        previous_code_hash: string;
        current_code_hash: string;
      };
      expect(state.is_contract).toBe(true);
      expect(state.code_hash_changed).toBe(true);
      expect(state.previous_code_hash).not.toBe(state.current_code_hash);
    });

    it('S8 (Permit Replay / Mutation): rejects with vault_rejection on mutated parameters', () => {
      expect(s8Fixture.expected_decision).toBe('vault_rejection');
      expect(s8Fixture.expected_balance_delta_yocto).toBe('0');

      const state = s8Fixture.initial_state as {
        vault_error_code: string;
        mutated_amount_yocto: string;
      };
      expect(state.vault_error_code).toBe('INVALID_PERMIT_NONCE_REPLAYED');
      expect(BigInt(state.mutated_amount_yocto)).toBeGreaterThan(0n);
    });

    it('S9 (Provider Outage): fails closed with infrastructure_error, mandatory source unavailable', () => {
      expect(s9Fixture.expected_decision).toBe('infrastructure_error');
      expect(s9Fixture.expected_reason_codes).toContain('MANDATORY_SOURCE_UNAVAILABLE');
      expect(s9Fixture.expected_reason_codes).toContain('INCOMPLETE_HISTORY');
      expect(s9Fixture.expected_signed).toBe(false);
      expect(s9Fixture.expected_submitted).toBe(false);
      expect(s9Fixture.expected_balance_delta_yocto).toBe('0');

      const state = s9Fixture.initial_state as {
        outage_provider: string;
        error_status_code: number;
      };
      expect(state.outage_provider).toBeDefined();
      expect(state.error_status_code).toBe(503);
    });

    it('S10 (Supported Method Call): allowlisted method call succeeds cleanly', () => {
      expect(s10Fixture.expected_decision).toBe('allow');
      expect(s10Fixture.proposed_action.kind).toBe('contract_call');
      if (s10Fixture.proposed_action.kind === 'contract_call') {
        expect(s10Fixture.proposed_action.method_name).toBe('claim_service');
      }
      expect(s10Fixture.expected_signed).toBe(true);
      expect(s10Fixture.expected_submitted).toBe(true);

      const state = s10Fixture.initial_state as {
        supported_methods: string[];
        unsupported_methods: string[];
      };
      expect(state.supported_methods).toContain('claim_service');
      expect(state.unsupported_methods).toContain('drain_funds');
    });
  });

  describe('Tier 3: Loader Utilities & Helper Functions', () => {
    it('loadScenarioFixture loads each scenario correctly by ID', () => {
      for (const id of CANONICAL_SCENARIO_IDS) {
        const fixture = loadScenarioFixture(id);
        expect(fixture.id).toBe(id);
      }
    });

    it('loadScenarioFixture throws on invalid ID', () => {
      expect(() => loadScenarioFixture('S0' as ScenarioId)).toThrow();
      expect(() => loadScenarioFixture('INVALID')).toThrow();
    });

    it('getAllScenarioFixtures returns record of 10 fixtures', () => {
      const all = getAllScenarioFixtures();
      expect(Object.keys(all).length).toBe(10);
      for (const id of CANONICAL_SCENARIO_IDS) {
        expect(all[id].id).toBe(id);
      }
    });

    it('listScenarioFixtures returns array of 10 fixtures in canonical order', () => {
      const list = listScenarioFixtures();
      expect(list.length).toBe(10);
      list.forEach((sc, idx) => {
        expect(sc.id).toBe(CANONICAL_SCENARIO_IDS[idx]);
      });
    });

    it('getScenarioReceiver extracts correct receiver IDs', () => {
      expect(getScenarioReceiver('S1')).toBe('merchant.testnet');
      expect(getScenarioReceiver('S2')).toBe('new-vendor.testnet');
      expect(getScenarioReceiver('S3')).toBe('known-drainer.testnet');
      expect(getScenarioReceiver('S4')).toBe('popular-service.testnet');
      expect(getScenarioReceiver('S5')).toBe('wash-trader.testnet');
      expect(getScenarioReceiver('S6')).toBe('user-b.testnet');
      expect(getScenarioReceiver('S7')).toBe('contract.testnet');
      expect(getScenarioReceiver('S8')).toBe('merchant.testnet');
      expect(getScenarioReceiver('S9')).toBe('unknown-target.testnet');
      expect(getScenarioReceiver('S10')).toBe('fixture.testnet');
    });

    it('getScenarioExpectedDecision extracts expected verdicts', () => {
      expect(getScenarioExpectedDecision('S1')).toBe('allow');
      expect(getScenarioExpectedDecision('S2')).toBe('warn');
      expect(getScenarioExpectedDecision('S3')).toBe('block');
      expect(getScenarioExpectedDecision('S4')).toBe('allow');
      expect(getScenarioExpectedDecision('S5')).toBe('warn');
      expect(getScenarioExpectedDecision('S6')).toBe('allow');
      expect(getScenarioExpectedDecision('S7')).toBe('warn');
      expect(getScenarioExpectedDecision('S8')).toBe('vault_rejection');
      expect(getScenarioExpectedDecision('S9')).toBe('infrastructure_error');
      expect(getScenarioExpectedDecision('S10')).toBe('allow');
    });

    it('getScenarioCanonicalPermit returns valid 64-hex permit when present', () => {
      const permit1 = getScenarioCanonicalPermit('S1');
      expect(permit1).not.toBeNull();
      expect(permit1?.permit_hash).toMatch(/^[a-f0-9]{64}$/);

      const permit3 = getScenarioCanonicalPermit('S3');
      expect(permit3).toBeNull();

      const permit9 = getScenarioCanonicalPermit('S9');
      expect(permit9).toBeNull();
    });
  });

  describe('Tier 4: Immutability & Serialization Roundtrip', () => {
    it('every scenario can be serialized to JSON and parsed identically', () => {
      for (const id of CANONICAL_SCENARIO_IDS) {
        const original = loadScenarioFixture(id);
        const jsonStr = JSON.stringify(original);
        const parsed = JSON.parse(jsonStr);
        const validated = ScenarioDefinitionSchema.parse(parsed);
        expect(validated).toEqual(original);
      }
    });
  });
});
