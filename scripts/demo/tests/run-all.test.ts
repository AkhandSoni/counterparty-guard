/**
 * @file scripts/demo/tests/run-all.test.ts
 * @description Comprehensive automated test suite for Demo Harness & Execution Adapters.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DemoExecutionLogSchema } from '@counterparty-guard/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  DeterministicAdapter,
  SandboxAdapter,
  TestnetAdapter,
  createExecutionAdapter,
} from '../harness/adapter.js';
import { runAllScenarios } from '../run-all.js';

describe('Demo Harness: DeterministicAdapter (S1–S10)', () => {
  let adapter: DeterministicAdapter;

  beforeAll(async () => {
    adapter = new DeterministicAdapter();
    await adapter.init();
  });

  afterAll(async () => {
    await adapter.teardown();
  });

  it('S1: Established Legitimate Receiver finalized with allow', async () => {
    const result = await adapter.executeScenario('S1');
    expect(result.passed).toBe(true);
    expect(result.log.decision).toBe('allow');
    expect(result.log.signed).toBe(true);
    expect(result.log.submitted).toBe(true);
    expect(result.log.finalized_outcome).toBe('finalized_transfer');
    expect(result.log.receiver_balance_delta).toBe('50000000000000000000000');
    expect(result.log.permit_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(result.log.reason_codes).toEqual([]);
    expect(DemoExecutionLogSchema.safeParse(result.log).success).toBe(true);
  });

  it('S2: Legitimate New Receiver pauses with warn awaiting owner approval', async () => {
    const result = await adapter.executeScenario('S2');
    expect(result.passed).toBe(true);
    expect(result.log.decision).toBe('warn');
    expect(result.log.signed).toBe(false);
    expect(result.log.submitted).toBe(false);
    expect(result.log.finalized_outcome).toBe('awaiting_owner_approval');
    expect(result.log.receiver_balance_delta).toBe('0');
    expect(result.log.reason_codes).toContain('RECENT_DEPLOYMENT');
    expect(result.log.reason_codes).toContain('UNKNOWN_AGE');
    expect(DemoExecutionLogSchema.safeParse(result.log).success).toBe(true);
  });

  it('S3: Reviewed Malicious Receiver blocked before signing', async () => {
    const result = await adapter.executeScenario('S3');
    expect(result.passed).toBe(true);
    expect(result.log.decision).toBe('block');
    expect(result.log.signed).toBe(false);
    expect(result.log.submitted).toBe(false);
    expect(result.log.finalized_outcome).toBe('aborted_before_signing');
    expect(result.log.receiver_balance_delta).toBe('0');
    expect(result.log.permit_hash).toBeNull();
    expect(result.log.reason_codes).toContain('ACTIVE_BLOCK');
    expect(result.log.reason_codes).toContain('REVIEWED_BLOCKLIST_MATCH');
    expect(DemoExecutionLogSchema.safeParse(result.log).success).toBe(true);
  });

  it('S4: Coordinated False-Report Flood discounts weight to 1.0 without hard block', async () => {
    const result = await adapter.executeScenario('S4');
    expect(result.passed).toBe(true);
    expect(result.log.decision).not.toBe('block');
    expect(result.log.decision).toBe('allow');
    expect(result.log.signed).toBe(true);
    expect(result.log.submitted).toBe(true);
    expect(result.log.finalized_outcome).toBe('finalized_transfer');
    expect(result.log.reason_codes).toContain('DEPENDENT_REPORTS');
    expect(DemoExecutionLogSchema.safeParse(result.log).success).toBe(true);
  });

  it('S5: Manufactured Circular Activity detects cycle and warns', async () => {
    const result = await adapter.executeScenario('S5');
    expect(result.passed).toBe(true);
    expect(result.log.decision).toBe('warn');
    expect(result.log.signed).toBe(false);
    expect(result.log.submitted).toBe(false);
    expect(result.log.finalized_outcome).toBe('awaiting_owner_approval');
    expect(result.log.receiver_balance_delta).toBe('0');
    expect(result.log.reason_codes).toContain('CIRCULAR_ACTIVITY');
    expect(DemoExecutionLogSchema.safeParse(result.log).success).toBe(true);
  });

  it('S6: Shared Common Faucet accounts exempted from clustering penalty', async () => {
    const result = await adapter.executeScenario('S6');
    expect(result.passed).toBe(true);
    expect(result.log.decision).toBe('allow');
    expect(result.log.reason_codes).toContain('COMMON_FAUCET_EXEMPTED');
    expect(result.log.reason_codes).not.toContain('DEPENDENT_REPORTS');
    expect(result.log.signed).toBe(true);
    expect(result.log.submitted).toBe(true);
    expect(result.log.finalized_outcome).toBe('finalized_transfer');
    expect(DemoExecutionLogSchema.safeParse(result.log).success).toBe(true);
  });

  it('S7: Upgraded Contract Receiver triggers CODE_CHANGED warning reassessment', async () => {
    const result = await adapter.executeScenario('S7');
    expect(result.passed).toBe(true);
    expect(result.log.decision).toBe('warn');
    expect(result.log.reason_codes).toContain('CODE_CHANGED');
    expect(result.log.signed).toBe(false);
    expect(result.log.submitted).toBe(false);
    expect(result.log.finalized_outcome).toBe('awaiting_owner_approval');
    expect(DemoExecutionLogSchema.safeParse(result.log).success).toBe(true);
  });

  it('S8: Mutated Permit Replay rejected on-chain by vault contract', async () => {
    const result = await adapter.executeScenario('S8');
    expect(result.passed).toBe(true);
    expect(result.log.finalized_outcome).toBe('vault_rejected');
    expect(result.log.receiver_balance_delta).toBe('0');
    expect(result.log.reason_codes).toContain('POLICY_LIMIT_EXCEEDED');
    expect(DemoExecutionLogSchema.safeParse(result.log).success).toBe(true);
  });

  it('S9: Provider Outage fails closed without permit', async () => {
    const result = await adapter.executeScenario('S9');
    expect(result.passed).toBe(true);
    expect(result.log.decision).toBe('block');
    expect(result.log.permit_hash).toBeNull();
    expect(result.log.signed).toBe(false);
    expect(result.log.submitted).toBe(false);
    expect(result.log.finalized_outcome).toBe('refused_source_outage');
    expect(result.log.receiver_balance_delta).toBe('0');
    expect(result.log.reason_codes).toContain('MANDATORY_SOURCE_UNAVAILABLE');
    expect(DemoExecutionLogSchema.safeParse(result.log).success).toBe(true);
  });

  it('S10: Supported Method Call succeeds cleanly', async () => {
    const result = await adapter.executeScenario('S10');
    expect(result.passed).toBe(true);
    expect(result.log.decision).toBe('allow');
    expect(result.log.signed).toBe(true);
    expect(result.log.submitted).toBe(true);
    expect(result.log.finalized_outcome).toBe('finalized_call');
    expect(result.log.receiver_balance_delta).toBe('10000000000000000000000');
    expect(DemoExecutionLogSchema.safeParse(result.log).success).toBe(true);
  });
});

describe('Demo Harness: Adapter Factory & Network Fallbacks', () => {
  it('createExecutionAdapter instantiates correct adapter class', () => {
    const deterministic = createExecutionAdapter('deterministic');
    expect(deterministic).toBeInstanceOf(DeterministicAdapter);
    expect(deterministic.mode).toBe('deterministic');

    const sandbox = createExecutionAdapter('sandbox');
    expect(sandbox).toBeInstanceOf(SandboxAdapter);
    expect(sandbox.mode).toBe('sandbox');

    const testnet = createExecutionAdapter('testnet');
    expect(testnet).toBeInstanceOf(TestnetAdapter);
    expect(testnet.mode).toBe('testnet');
  });

  it('SandboxAdapter handles offline sandbox node gracefully with fallback', async () => {
    const sandbox = new SandboxAdapter({ rpcUrl: 'http://127.0.0.1:59999' }); // non-existent port
    await sandbox.init();
    const result = await sandbox.executeScenario('S1', { fallbackToDeterministic: true });
    expect(result.passed).toBe(true);
    expect(result.mode).toBe('sandbox');
    expect(result.log.decision).toBe('allow');
    await sandbox.teardown();
  });

  it('TestnetAdapter handles unreachable testnet gracefully with fallback', async () => {
    const testnet = new TestnetAdapter({ rpcUrl: 'https://unreachable.testnet.near.invalid' });
    await testnet.init();
    const result = await testnet.executeScenario('S1', { fallbackToDeterministic: true });
    expect(result.passed).toBe(true);
    expect(result.mode).toBe('testnet');
    expect(result.log.decision).toBe('allow');
    await testnet.teardown();
  });
});

describe('Demo Harness: Programmatic runAllScenarios Runner', () => {
  let tempDir: string;

  beforeAll(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-run-all-test-'));
  });

  afterAll(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  });

  it('executes all 10 scenarios in sequence and returns complete summary', async () => {
    const logFilePath = path.join(tempDir, 'demo-all.jsonl');
    const summary = await runAllScenarios({ mode: 'deterministic', logFilePath });
    expect(summary.totalScenarios).toBe(10);
    expect(summary.passedScenarios).toBe(10);
    expect(summary.failedScenarios).toBe(0);
    expect(summary.passedAssertions).toBe(summary.totalAssertions);
    expect(summary.totalAssertions).toBeGreaterThanOrEqual(50);
    expect(summary.results.length).toBe(10);

    const scenarioIds = summary.results.map((r) => r.scenarioId);
    expect(scenarioIds).toEqual(['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9', 'S10']);
  });

  it('filters by single scenario when scenarioId option is supplied', async () => {
    const logFilePath = path.join(tempDir, 'single-s3.jsonl');
    const summary = await runAllScenarios({ mode: 'deterministic', scenarioId: 'S3', logFilePath });
    expect(summary.totalScenarios).toBe(1);
    expect(summary.passedScenarios).toBe(1);
    expect(summary.results[0].scenarioId).toBe('S3');
    expect(summary.results[0].log.decision).toBe('block');
  });
});
