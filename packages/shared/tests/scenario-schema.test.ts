import { describe, expect, it } from 'vitest';
import { CheckRequestSchema, ReasonCodeSchema } from '../src/schemas/check.js';
import {
  DemoExecutionLogSchema,
  ScenarioDefinitionSchema,
  ScenarioIdSchema,
} from '../src/schemas/scenario.js';

describe('Scenario & Check Action Schemas', () => {
  it('validates canonical scenario IDs S1 through S10', () => {
    const validIds = ['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9', 'S10'];
    for (const id of validIds) {
      expect(ScenarioIdSchema.safeParse(id).success).toBe(true);
    }
    expect(ScenarioIdSchema.safeParse('S0').success).toBe(false);
    expect(ScenarioIdSchema.safeParse('S11').success).toBe(false);
  });

  it('validates a complete Scenario definition fixture', () => {
    const sampleS1Fixture = {
      id: 'S1' as const,
      name: 'Legitimate Established Receiver',
      description: 'Account with high age and verified history produces immediate allow.',
      security_invariant: 'Established account with clean history receives allow and valid permit.',
      network: 'testnet' as const,
      proposed_action: {
        kind: 'transfer_near' as const,
        receiver_id: 'established-receiver.testnet',
        amount_yocto: '1000000000000000000000000',
      },
      expected_decision: 'allow' as const,
      expected_reason_codes: [],
      expected_signed: true,
      expected_submitted: true,
      expected_balance_delta_yocto: '1000000000000000000000000',
      initial_state: {
        account_age_days: 180,
        tx_count: 520,
      },
    };
    const res = ScenarioDefinitionSchema.safeParse(sampleS1Fixture);
    expect(res.success).toBe(true);
  });

  it('validates discriminated action union for contract calls', () => {
    const callAction = {
      kind: 'contract_call' as const,
      receiver_id: 'vault.testnet',
      method_name: 'deposit_and_stake',
      args_base64: 'e30=',
      attached_deposit_yocto: '5000000000000000000000000',
      gas_tgas: 50,
    };
    const checkReq = {
      schema_version: 1 as const,
      network: 'testnet' as const,
      vault_id: 'agent-vault.testnet',
      request_id: 'req-001',
      action: callAction,
    };
    const res = CheckRequestSchema.safeParse(checkReq);
    expect(res.success).toBe(true);
  });

  it('validates all canonical ReasonCodes including ACTIVE_BLOCK and COMMON_FAUCET_EXEMPTED', () => {
    const validCodes = [
      'ACTIVE_BLOCK',
      'REVIEWED_BLOCKLIST_MATCH',
      'CODE_CHANGED',
      'RECENT_DEPLOYMENT',
      'DEPENDENT_REPORTS',
      'CIRCULAR_ACTIVITY',
      'COMMON_FAUCET_EXEMPTED',
      'UNKNOWN_AGE',
      'INCOMPLETE_HISTORY',
      'MANDATORY_SOURCE_UNAVAILABLE',
      'POLICY_LIMIT_EXCEEDED',
    ];
    for (const code of validCodes) {
      expect(ReasonCodeSchema.safeParse(code).success).toBe(true);
    }
    expect(ReasonCodeSchema.safeParse('UNKNOWN_REASON_CODE').success).toBe(false);
  });

  it('validates S3 scenario fixture containing ACTIVE_BLOCK reason code', () => {
    const s3Fixture = {
      id: 'S3' as const,
      name: 'Reviewed Malicious Receiver',
      description: 'Account with active reviewed blocklist match produces block.',
      security_invariant: 'Active reviewed block requires human reviewer action.',
      network: 'testnet' as const,
      proposed_action: {
        kind: 'transfer_near' as const,
        receiver_id: 'malicious.testnet',
        amount_yocto: '5000000000000000000000000',
      },
      expected_decision: 'block' as const,
      expected_reason_codes: ['ACTIVE_BLOCK' as const],
      expected_signed: false,
      expected_submitted: false,
      expected_balance_delta_yocto: '0',
      initial_state: {
        blocklist_revision: 7,
        block_reason: 'Confirmed drainer',
      },
    };
    const res = ScenarioDefinitionSchema.safeParse(s3Fixture);
    expect(res.success).toBe(true);
  });

  it('validates DemoExecutionLogSchema matching demo harness requirements', () => {
    const validLog = {
      run_id: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
      scenario_id: 'S3' as const,
      mode: 'deterministic' as const,
      injected_prompt_hash:
        'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      decision: 'block' as const,
      reason_codes: ['ACTIVE_BLOCK'],
      permit_hash: null,
      signed: false,
      submitted: false,
      finalized_outcome: 'aborted_before_signing',
      receiver_balance_delta: '0',
    };
    expect(DemoExecutionLogSchema.safeParse(validLog).success).toBe(true);

    const invalidMode = { ...validLog, mode: 'invalid_mode' };
    expect(DemoExecutionLogSchema.safeParse(invalidMode).success).toBe(false);

    const invalidScenario = { ...validLog, scenario_id: 'S99' };
    expect(DemoExecutionLogSchema.safeParse(invalidScenario).success).toBe(false);
  });
});
