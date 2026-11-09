import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { checkResponseSchema, permitHash } from '@counterparty-guard/shared';
import { DeterministicAdapter, SandboxAdapter, TestnetAdapter, createExecutionAdapter } from '../harness/adapter.js';
import { runAllScenarios } from '../run-all.js';
const directories: string[] = [];
afterEach(() => { vi.unstubAllGlobals(); for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true }); });
describe('actual A+C fixture assessments and unavailable chain adapters', () => {
  it.each([['S1','allow'],['S2','warn'],['S3','block'],['S4','allow'],['S5','warn'],['S6','allow'],['S7','warn'],['S10','allow']] as const)('%s assesses %s without inventing chain execution', async (id, decision) => {
    const result = await new DeterministicAdapter().executeScenario(id);
    expect(result.passed).toBe(true); expect(result.log.decision).toBe(decision);
    expect(result.log.signed).toBe(false); expect(result.log.submitted).toBe(false);
    expect(result.log.source_mode).toBe('fixture'); expect(result.log.execution_environment).toBe('not-executed');
    expect(result.log.receiver_balance_delta).toBe('0');
    const check = checkResponseSchema.parse(result.checkResponse);
    if (decision === 'block') expect(check.permit).toBeNull();
    else {
      expect(check.permit).not.toBeNull(); expect(check.permit?.permit_hash).toBe(permitHash(check.permit!.payload));
      expect(check.permit?.payload.network).toBe('sandbox'); expect(check.permit?.payload.verdict).toBe(decision);
    }
  });
  it('does not turn an outage into a malicious-receiver verdict', async () => {
    const result=await new DeterministicAdapter().executeScenario('S9');
    expect(result.log.decision).toBe('error'); expect(result.log.permit_hash).toBeNull(); expect(result.passed).toBe(true);
  });
  it('leaves replay/mutation enforcement explicitly unavailable until B implements it', async () => {
    const result=await new DeterministicAdapter().executeScenario('S8');
    expect(result.passed).toBe(false); expect(result.log.finalized_outcome).toBe('execution_unavailable'); expect(result.log.submitted).toBe(false);
  });
  it.each([SandboxAdapter,TestnetAdapter])('never relabels deterministic results when a status RPC would succeed', async Adapter => {
    const fetcher=vi.fn(async()=>new Response(JSON.stringify({result:{chain_id:'testnet'}})));
    vi.stubGlobal('fetch',fetcher);
    const adapter=new Adapter({rpcUrl:'https://fixture.invalid'}); await adapter.init();
    const result=await adapter.executeScenario('S1',{fallbackToDeterministic:true});
    expect(result.passed).toBe(false); expect(result.log.decision).toBe('error'); expect(result.log.source_mode).toBeNull();
    expect(result.log.signed).toBe(false); expect(result.log.submitted).toBe(false); expect(result.log.permit_hash).toBeNull(); expect(fetcher).not.toHaveBeenCalled();
  });
  it('runs assessments and records the remaining B execution gate without claiming a complete demo', async () => {
    const directory=mkdtempSync(join(tmpdir(),'guard-demo-')); directories.push(directory);
    const logFilePath=join(directory,'run.jsonl'); const summary=await runAllScenarios({logFilePath});
    expect(summary.totalScenarios).toBe(10); expect(summary.failedScenarios).toBe(1);
    expect(summary.results.find(result=>result.scenarioId==='S8')?.passed).toBe(false);
    const logs=readFileSync(logFilePath,'utf8').trim().split('\n').map(line=>JSON.parse(line));
    expect(logs).toHaveLength(10); expect(logs.every(log=>!log.signed&&!log.submitted)).toBe(true);
  });
  it('keeps adapter selection explicit', () => {
    expect(createExecutionAdapter()).toBeInstanceOf(DeterministicAdapter);
    expect(createExecutionAdapter('sandbox')).toBeInstanceOf(SandboxAdapter);
    expect(()=>createExecutionAdapter('bogus' as 'testnet')).toThrow();
  });
});
