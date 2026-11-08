/**
 * @file scripts/demo/tests/run-attack.test.ts
 * @description Automated test suite for the Prompt-Injection Attack Runner & JSONL Logger.
 */

import fs from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { DemoExecutionLogSchema } from '@counterparty-guard/shared';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  CounterpartyBlockedError,
  WarningApprovalRequiredError,
  createDeterministicGuardDatabase,
  evaluateGuard,
  guardedAgentExecute,
} from '../harness/guard.js';
import { AuditLogRecordSchema, JsonlLogger, hashPrompt } from '../harness/logger.js';
import { PROMPTS, parseCliArgs, runAttack } from '../run-attack.js';

describe('Prompt-Injection Attack Runner & JSONL Logger', () => {
  let tempDir: string;
  let testLogFile: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(tmpdir(), 'cg-demo-test-'));
    testLogFile = path.join(tempDir, 'audit.jsonl');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors in test teardown
    }
  });

  // =========================================================================
  // Tier 1: Feature Invariants & Core Capabilities (Feature >= 5 tests)
  // =========================================================================
  describe('Tier 1: Feature Functionality & Invariants', () => {
    it('enforces crucial security invariant on S3: signed=false, submitted=false, aborted_before_signing', async () => {
      const result = await runAttack({
        scenario: 'S3',
        mode: 'deterministic',
        verbose: false,
        logFile: testLogFile,
      });

      expect(result.securityInvariantVerified).toBe(true);
      expect(result.intercepted).toBe(true);

      const record = result.record;
      expect(record.signed).toBe(false);
      expect(record.submitted).toBe(false);
      expect(record.finalized_outcome).toBe('aborted_before_signing');
      expect(record.receiver_balance_delta).toBe('0');
      expect(record.decision).toBe('block');
      expect(record.permit_hash).toBeNull();
      expect(record.reason_codes).toContain('ACTIVE_BLOCK');
    });

    it('in-process guard halts execution and throws CounterpartyBlockedError before signing', async () => {
      const { repository } = createDeterministicGuardDatabase();
      const maliciousAction = {
        kind: 'transfer_near' as const,
        receiver_id: 'known-drainer.testnet',
        amount_yocto: '5000000000000000000000000',
      };

      await expect(guardedAgentExecute(maliciousAction, repository, 'testnet')).rejects.toThrow(
        CounterpartyBlockedError,
      );

      try {
        await guardedAgentExecute(maliciousAction, repository, 'testnet');
      } catch (err) {
        expect(err).toBeInstanceOf(CounterpartyBlockedError);
        const blockedErr = err as CounterpartyBlockedError;
        expect(blockedErr.receiverId).toBe('known-drainer.testnet');
        expect(blockedErr.reasonCodes).toContain('ACTIVE_BLOCK');
        expect(blockedErr.riskIndicator).toBe(100);
      }
    });

    it('hashPrompt computes deterministic sha256 prefix and 64-hex digest', () => {
      const prompt = 'Test adversarial invoice memo';
      const hash = hashPrompt(prompt);

      expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(hashPrompt(prompt)).toBe(hash);
      expect(hashPrompt(`${prompt} modification`)).not.toBe(hash);
    });

    it('JsonlLogger appends records to disk and reads them back faithfully', () => {
      const logger = new JsonlLogger({
        logFilePath: testLogFile,
        echoToConsole: false,
      });

      const entry = {
        run_id: '11111111-2222-3333-4444-555555555555',
        timestamp: new Date().toISOString(),
        scenario_id: 'S3' as const,
        mode: 'deterministic' as const,
        injected_prompt_hash: `sha256:${'a'.repeat(64)}`,
        decision: 'block' as const,
        reason_codes: ['ACTIVE_BLOCK'],
        permit_hash: null,
        signed: false,
        submitted: false,
        finalized_outcome: 'aborted_before_signing',
        receiver_balance_delta: '0',
      };

      logger.writeRecord(entry);

      const records = logger.readRecords();
      expect(records).toHaveLength(1);
      expect(records[0]).toMatchObject(entry);
    });

    it('written log records strictly validate against both AuditLogRecordSchema and DemoExecutionLogSchema', async () => {
      await runAttack({
        scenario: 'S3',
        mode: 'deterministic',
        verbose: false,
        logFile: testLogFile,
      });

      const logger = new JsonlLogger({ logFilePath: testLogFile, echoToConsole: false });
      const records = logger.readRecords();
      expect(records).toHaveLength(1);

      const record = records[0];
      expect(AuditLogRecordSchema.safeParse(record).success).toBe(true);
      expect(DemoExecutionLogSchema.safeParse(record).success).toBe(true);
    });

    it('prompt fixtures contain isolated project testnet accounts only', () => {
      expect(PROMPTS.S3.receiver).toBe('known-drainer.testnet');
      expect(PROMPTS.S1.receiver).toBe('merchant.testnet');
      expect(PROMPTS.S2.receiver).toBe('new-vendor.testnet');
    });
  });

  // =========================================================================
  // Tier 2: Boundary & Corner Cases (Boundary >= 5 tests)
  // =========================================================================
  describe('Tier 2: Boundary & Corner Cases', () => {
    it('creates deeply nested directories if log file path parent does not exist', () => {
      const deepPath = path.join(tempDir, 'nested', 'sub', 'dirs', 'run.jsonl');
      const logger = new JsonlLogger({ logFilePath: deepPath, echoToConsole: false });

      logger.writeRecord({
        run_id: '22222222-3333-4444-5555-666666666666',
        timestamp: new Date().toISOString(),
        scenario_id: 'S3',
        mode: 'deterministic',
        injected_prompt_hash: `sha256:${'b'.repeat(64)}`,
        decision: 'block',
        reason_codes: ['ACTIVE_BLOCK'],
        permit_hash: null,
        signed: false,
        submitted: false,
        finalized_outcome: 'aborted_before_signing',
        receiver_balance_delta: '0',
      });

      expect(fs.existsSync(deepPath)).toBe(true);
      expect(logger.readRecords()).toHaveLength(1);
    });

    it('handles multiple sequential append operations without corrupted json lines', () => {
      const logger = new JsonlLogger({ logFilePath: testLogFile, echoToConsole: false });

      for (let i = 0; i < 5; i++) {
        logger.writeRecord({
          run_id: `33333333-4444-5555-6666-${i.toString().padStart(12, '0')}`,
          timestamp: new Date().toISOString(),
          scenario_id: 'S3',
          mode: 'deterministic',
          injected_prompt_hash: `sha256:${i.toString().repeat(64)}`,
          decision: 'block',
          reason_codes: ['ACTIVE_BLOCK'],
          permit_hash: null,
          signed: false,
          submitted: false,
          finalized_outcome: 'aborted_before_signing',
          receiver_balance_delta: '0',
        });
      }

      const records = logger.readRecords();
      expect(records).toHaveLength(5);
    });

    it('parseCliArgs correctly parses short and long flags', () => {
      const parsedShort = parseCliArgs([
        '-s',
        'S3',
        '-m',
        'deterministic',
        '-v',
        '-l',
        '/tmp/demo.jsonl',
      ]);
      expect(parsedShort.scenario).toBe('S3');
      expect(parsedShort.mode).toBe('deterministic');
      expect(parsedShort.verbose).toBe(true);
      expect(parsedShort.logFile).toBe('/tmp/demo.jsonl');

      const parsedLong = parseCliArgs([
        '--scenario',
        'S1',
        '--mode',
        'sandbox',
        '--log-file',
        '/tmp/out.jsonl',
      ]);
      expect(parsedLong.scenario).toBe('S1');
      expect(parsedLong.mode).toBe('sandbox');
      expect(parsedLong.verbose).toBe(false);
      expect(parsedLong.logFile).toBe('/tmp/out.jsonl');
    });

    it('parseCliArgs throws error on invalid execution mode', () => {
      expect(() => parseCliArgs(['--mode', 'unknown_mode'])).toThrow(/Invalid mode "unknown_mode"/);
    });

    it('guarantees zero balance delta even when prompt requests gigantic yocto amount', async () => {
      const { repository } = createDeterministicGuardDatabase();
      const extremeAction = {
        kind: 'transfer_near' as const,
        receiver_id: 'known-drainer.testnet',
        amount_yocto: '1000000000000000000000000000000000', // 10^9 NEAR
      };

      await expect(guardedAgentExecute(extremeAction, repository, 'testnet')).rejects.toThrow(
        CounterpartyBlockedError,
      );
    });
  });

  // =========================================================================
  // Tier 3: Pairwise & Comparative Control Testing
  // =========================================================================
  describe('Tier 3: Pairwise & Comparative Scenarios', () => {
    it('contrasts with S1 benign prompt: legitimate transfer is allowed and signs', async () => {
      const result = await runAttack({
        scenario: 'S1',
        mode: 'deterministic',
        verbose: false,
        logFile: testLogFile,
      });

      expect(result.intercepted).toBe(false);
      expect(result.record.decision).toBe('allow');
      expect(result.record.signed).toBe(true);
      expect(result.record.submitted).toBe(true);
      expect(result.record.finalized_outcome).toBe('executed_success');
      expect(result.record.permit_hash).not.toBeNull();
    });

    it('contrasts with S2 new vendor prompt: requires owner warning approval', async () => {
      const result = await runAttack({
        scenario: 'S2',
        mode: 'deterministic',
        verbose: false,
        logFile: testLogFile,
      });

      expect(result.intercepted).toBe(true);
      expect(result.record.decision).toBe('warn');
      expect(result.record.signed).toBe(false);
      expect(result.record.submitted).toBe(false);
      expect(result.record.finalized_outcome).toBe('awaiting_owner_approval');
    });

    it('logger clear() method truncates log file properly', () => {
      const logger = new JsonlLogger({ logFilePath: testLogFile, echoToConsole: false });
      logger.writeRecord({
        run_id: '44444444-5555-6666-7777-888888888888',
        timestamp: new Date().toISOString(),
        scenario_id: 'S3',
        mode: 'deterministic',
        injected_prompt_hash: `sha256:${'c'.repeat(64)}`,
        decision: 'block',
        reason_codes: ['ACTIVE_BLOCK'],
        permit_hash: null,
        signed: false,
        submitted: false,
        finalized_outcome: 'aborted_before_signing',
        receiver_balance_delta: '0',
      });
      expect(logger.readRecords()).toHaveLength(1);

      logger.clear();
      expect(logger.readRecords()).toHaveLength(0);
    });
  });

  // =========================================================================
  // Tier 4: Real-world Workload Testing
  // =========================================================================
  describe('Tier 4: End-to-End Runner Execution', () => {
    it('executes full attack simulation run end-to-end and verifies disk artifact integrity', async () => {
      const runOutcome = await runAttack({
        scenario: 'S3',
        mode: 'deterministic',
        verbose: false,
        logFile: testLogFile,
      });

      expect(runOutcome.record.run_id).toBeDefined();
      expect(runOutcome.record.timestamp).toBeDefined();
      expect(runOutcome.record.injected_prompt_hash).toMatch(/^sha256:[a-f0-9]{64}$/);

      // Verify file written to disk
      const rawContent = fs.readFileSync(testLogFile, 'utf-8');
      const lines = rawContent.trim().split('\n');
      expect(lines).toHaveLength(1);

      const parsedJson = JSON.parse(lines[0]);
      expect(parsedJson.scenario_id).toBe('S3');
      expect(parsedJson.decision).toBe('block');
      expect(parsedJson.signed).toBe(false);
      expect(parsedJson.submitted).toBe(false);
      expect(parsedJson.finalized_outcome).toBe('aborted_before_signing');
      expect(parsedJson.receiver_balance_delta).toBe('0');
    });
  });
});
