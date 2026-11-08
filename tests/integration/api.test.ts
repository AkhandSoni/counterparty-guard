import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  publicKeyFromKeyObject, signPermit, verifySignedPermit, checkResponseSchema,
  type AgentRegistration, type CheckRequest, type CheckResponse, type ExecutionObservation,
  type PolicySnapshot, type ReceiverEvidence, type ReputationSnapshot,
} from '@counterparty-guard/shared';
import { createApp } from '../../apps/api/src/app.js';
import { GuardStore, credentialHash, digest } from '../../apps/api/src/storage/store.js';
import { AssessmentService } from '../../apps/api/src/services/assess.js';

const keys = generateKeyPairSync('ed25519');
const publicKey = publicKeyFromKeyObject(keys.publicKey);
const agentPublicKey = publicKeyFromKeyObject(generateKeyPairSync('ed25519').publicKey);
const token = 'test-agent-credential-for-integration-0001';
const otherToken = 'test-agent-credential-for-integration-0002';
const complete = { complete: true, truncated: false, pages: 1, window_start_ms: null, window_end_ms: null, notes: [] };
const initialNow = 1_800_000_000_000;
const registrations: AgentRegistration[] = [
  { agent_id: 'agent-one', account_id: 'agent-one.testnet', public_key: agentPublicKey, credential_hash: credentialHash(token), network: 'sandbox', vault_id: 'vault.testnet' },
  { agent_id: 'agent-two', account_id: 'agent-two.testnet', public_key: agentPublicKey, credential_hash: credentialHash(otherToken), network: 'sandbox', vault_id: 'vault.testnet' },
];
const cleanups: (() => void | Promise<void>)[] = [];
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });

function fixture(options: { path?: string; register?: boolean; reportPlugin?: Parameters<typeof createApp>[0]['reportPlugin'] } = {}) {
  let now = initialNow;
  const store = new GuardStore(options.path);
  cleanups.push(() => store.close());
  if (options.register !== false) for (const registration of registrations) store.registerAgent(registration, now);
  let policy: PolicySnapshot = { network: 'sandbox', vault_id: 'vault.testnet', deployment_instance_id: '11'.repeat(32), revision: '1', observed_at: now, paused: false, max_action_yocto: '100000000000000000000000', permit_ttl_ms: 120_000, max_source_age_ms: 60_000, supported_call: { receiver_id: 'receiver.testnet', method_name: 'accept_memo', max_gas_tgas: 50, max_deposit_yocto: '10000000000000000000000', argument_schema: 'memo-v1' } };
  let evidence: ReceiverEvidence = { network: 'sandbox', source_mode: 'fixture', account_id: 'receiver.testnet', exists: true, code_identity: 'code-v1', account_age_days: 100, recent_deployment: false, independent_successful_counterparties: 15, transfer_count: 30, activity_manipulation_score: 0, observations: [{ id: 'fixture:account', kind: 'account_state', network: 'sandbox', source_mode: 'fixture', source: 'fixture', fetched_at: now, source_timestamp: now, block_height: '10', block_hash: 'fixture-block', coverage: complete, raw_hash: digest({ exists: true }), value: { exists: true } }], coverage: complete, observed_at: now };
  let reputation: ReputationSnapshot = { network: 'sandbox', account_id: 'receiver.testnet', blocklist_revision: '1', observed_at: now, available: true, active_blocks: [], unresolved_report_weight: 0, dependent_report_groups: 0, manipulation_score: 0, explanations: [], coverage: complete };
  let unavailable = false;
  let signCount = 0;
  let refreshCount = 0;
  let signHook: (() => Promise<void>) | null = null;
  const dependencies = {
    store, sourceMode: 'fixture' as const, scorerPublicKey: publicKey, clock: () => now,
    receiverProvider: { sourceMode: 'fixture' as const, async assess(input: { refresh?: boolean }) { if (unavailable) throw new Error('https://secret-token@private-provider'); if (input.refresh) refreshCount++; return structuredClone(evidence); } },
    policyProvider: { async getPolicy() { return structuredClone(policy); } },
    reputationProvider: { async getReputation() { return structuredClone(reputation); } },
    signPermit: async (payload: Parameters<typeof signPermit>[0]) => { signCount++; if (signHook) await signHook(); return signPermit(payload, keys.privateKey); },
  };
  const app = createApp({ ...dependencies, ...(options.reportPlugin ? { reportPlugin: options.reportPlugin } : {}) });
  cleanups.push(() => app.close());
  const request: CheckRequest = { schema_version: 1, network: 'sandbox', vault_id: 'vault.testnet', request_id: 'request-one', action: { kind: 'transfer_near', receiver_id: 'receiver.testnet', amount_yocto: '10000000000000000000000' } };
  const post = (body: unknown = request, credential = token) => app.inject({ method: 'POST', url: '/v1/checks', headers: { authorization: `Bearer ${credential}` }, payload: body as Record<string, unknown> });
  const get = (url: string, credential = token) => app.inject({ method: 'GET', url, headers: { authorization: `Bearer ${credential}` } });
  const revalidate = (id: string) => app.inject({ method: 'POST', url: `/v1/checks/${id}/revalidate`, headers: { authorization: `Bearer ${token}` } });
  return {
    app, store, dependencies, request, post, get, revalidate,
    advance(ms: number) { now += ms; },
    fresh() { evidence.observed_at = now; for (const observation of evidence.observations) { observation.fetched_at = now; observation.source_timestamp = now; } policy.observed_at = now; reputation.observed_at = now; },
    setEvidence(change: Partial<ReceiverEvidence>) { evidence = { ...evidence, ...change }; },
    setPolicy(change: Partial<PolicySnapshot>) { policy = { ...policy, ...change }; },
    setReputation(change: Partial<ReputationSnapshot>) { reputation = { ...reputation, ...change }; },
    setUnavailable(value: boolean) { unavailable = value; },
    setSignHook(hook: () => Promise<void>) { signHook = hook; },
    get signCount() { return signCount; }, get refreshCount() { return refreshCount; },
  };
}

async function allow(f: ReturnType<typeof fixture>) {
  const response = await f.post();
  expect(response.statusCode, response.body).toBe(200);
  const body = response.json();
  expect(body.decision).toBe('allow');
  return body;
}

function finalize(f: ReturnType<typeof fixture>, check: CheckResponse, blockHeight: string, observedAt: number, receiptId = check.check_id) {
  if (!check.permit) throw new Error('Expected an issued permit');
  const observation: ExecutionObservation = {
    execution_id: check.check_id, check_id: check.check_id, network: 'sandbox', vault_id: 'vault.testnet',
    permit_hash: check.permit.permit_hash, state: 'succeeded', transaction_id: `fixture-tx-${receiptId}`,
    receipt_id: `fixture-receipt-${receiptId}`, block_height: blockHeight, block_hash: `fixture-block-${blockHeight}`,
    observed_at: observedAt, finalized: true, nonexecution_proven: false,
    owner_approval_ref: check.decision === 'warn' ? `fixture-owner-${check.permit.permit_hash}` : null,
  };
  f.store.reconcile(observation);
  return observation;
}

describe('authenticated assessment and durable issuance', () => {
  it('signs reconstructed actions, retains evidence, and reuses the assessment on idempotent retries', async () => {
    const f = fixture();
    const result = await allow(f);
    expect(verifySignedPermit(result.permit, publicKey)).toBe(true);
    expect(result.attestation).toBeNull();
    expect(result.permit.payload.action).toEqual(f.request.action);
    expect((await f.post()).json()).toEqual(result);
    expect(f.signCount).toBe(1);
    expect((await f.get(`/v1/checks/${result.check_id}`)).json()).toEqual(result);
    expect((await f.get('/v1/receivers/sandbox/receiver.testnet')).json().evidence.source_mode).toBe('fixture');
    const attempt = (await f.get(`/v1/executions/${result.check_id}`)).json();
    expect(attempt.stage).toBe('attempted');
    expect(attempt.signed).toBe(false);
    expect(attempt.submitted).toBe(false);
    expect(f.store.database.prepare('SELECT snapshot_json FROM evidence_snapshots').get()).toBeTruthy();
  });
  it('rejects reused provisioning credentials and envelopes signed by an untrusted scorer', async () => {
    const f = fixture();
    expect(() => f.store.registerAgent({ ...registrations[1]!, agent_id: 'third-agent', credential_hash: registrations[0]!.credential_hash })).toThrow('already bound');
    const attacker = generateKeyPairSync('ed25519');
    const app = createApp({ ...f.dependencies, signPermit: payload => signPermit(payload, attacker.privateKey) });
    cleanups.push(() => app.close());
    const result = await app.inject({ method: 'POST', url: '/v1/checks', headers: { authorization: `Bearer ${token}` }, payload: f.request });
    expect(result.statusCode).toBe(500);
    expect(result.json().permit).toBeNull();
    expect(f.store.database.prepare('SELECT COUNT(*) AS n FROM permit_records').get()).toEqual({ n: 0 });
  });
  it('requires separate agent and scorer keys', async () => {
    const f = fixture();
    const credential = 'same-key-agent-credential-0001';
    f.store.registerAgent({ ...registrations[0]!, agent_id: 'same-key-agent', public_key: publicKey, credential_hash: credentialHash(credential) });
    const result = await f.post(f.request, credential);
    expect(result.statusCode).toBe(403);
    expect(result.json().permit).toBeNull();
    expect(f.signCount).toBe(0);
  });
  it('isolates retained evidence from reputation-adapter annotations during signing', async () => {
    const f = fixture();
    let reads = 0;
    const original = f.dependencies.reputationProvider.getReputation;
    const app = createApp({ ...f.dependencies, reputationProvider: {
      async getReputation(_network, _accountId, evidence) {
        reads++;
        if (reads === 3) {
          evidence.exists = false;
          evidence.observations[0]!.value = { annotation: 'adapter-local-only' };
        }
        return original();
      },
    } });
    cleanups.push(() => app.close());
    const result = await app.inject({ method: 'POST', url: '/v1/checks', headers: { authorization: `Bearer ${token}` }, payload: f.request });
    expect(result.statusCode).toBe(200);
    const retained = (await f.get(`/v1/checks/${result.json().check_id}/evidence`)).json();
    expect(retained.snapshot.evidence.exists).toBe(true);
    expect(retained.snapshot.evidence.observations[0].value).toEqual({ exists: true });
    expect(retained.evidence_snapshot_hash).toBe(result.json().permit.payload.evidence_snapshot_hash);
  });
  it('rejects changed actions and context under one request ID without new signatures', async () => {
    const f = fixture();
    await allow(f);
    const changed = await f.post({ ...f.request, action: { ...f.request.action, amount_yocto: '1' } });
    expect(changed.statusCode).toBe(409);
    expect(changed.json().error.code).toBe('REQUEST_CONFLICT');
    expect(f.signCount).toBe(1);
    const wrongVault = await f.post({ ...f.request, vault_id: 'other-vault.testnet' });
    expect(wrongVault.statusCode).toBe(403);
  });
  it('derives agent identity from credentials and denies cross-agent history and policy', async () => {
    const f = fixture();
    const result = await allow(f);
    expect((await f.get(`/v1/checks/${result.check_id}`, otherToken)).statusCode).toBe(404);
    expect((await f.get(`/v1/executions/${result.check_id}`, otherToken)).statusCode).toBe(404);
    expect((await f.get('/v1/receivers/sandbox/receiver.testnet', otherToken)).statusCode).toBe(404);
    expect((await f.post({ ...f.request, request_id: 'spoof', agent_id: 'agent-two' })).statusCode).toBe(400);
    expect((await f.app.inject({ method: 'POST', url: '/v1/checks', payload: f.request })).statusCode).toBe(401);
    expect((await f.post(f.request, 'invalid-credential-0000')).statusCode).toBe(401);
    expect((await f.get('/v1/receivers/testnet/receiver.testnet')).statusCode).toBe(403);
  });
  it('never signs a reviewed block or accepts Boolean warning approval', async () => {
    const f = fixture();
    f.setReputation({ active_blocks: [{ id: 'reviewed-fixture', network: 'sandbox', account_id: 'receiver.testnet', code_identity: null, expires_at: initialNow + 300_000, reviewed_by: 'independent-reviewer', evidence_refs: ['fixture:reviewed-reference'] }] });
    const block = await f.post();
    expect(block.statusCode).toBe(200);
    expect(block.json().decision).toBe('block');
    expect(block.json().permit).toBeNull();
    expect(f.signCount).toBe(0);
    expect(f.store.database.prepare('SELECT COUNT(*) AS n FROM permit_records').get()).toEqual({ n: 0 });
    f.setReputation({ active_blocks: [] });
    f.setEvidence({ account_age_days: null });
    const warning = await f.post({ ...f.request, request_id: 'warning' });
    expect(warning.json().decision).toBe('warn');
    expect(warning.json().permit.payload.verdict).toBe('warn');
    const boolean = await f.post({ ...f.request, request_id: 'boolean', approved: true });
    expect(boolean.statusCode).toBe(400);
    expect((await f.get(`/v1/executions/${warning.json().check_id}`)).json().submitted).toBe(false);
  });
  it('fails closed on unavailable mandatory inputs, stale underlying blocks and unavailable reputation', async () => {
    const f = fixture();
    f.setUnavailable(true);
    const outage = await f.post();
    expect(outage.statusCode).toBe(503);
    expect(outage.json().permit).toBeNull();
    expect(outage.body).not.toContain('secret-token');
    expect(f.signCount).toBe(0);
    f.setUnavailable(false);
    f.advance(60_001);
    const stale = await f.post();
    expect(stale.statusCode).toBe(503);
    expect(stale.json().error.code).toBe('SOURCE_STALE');
    f.fresh();
    f.setReputation({ available: false });
    expect((await f.post()).statusCode).toBe(503);
    expect(f.signCount).toBe(0);
    f.setReputation({ available: true });
    expect((await f.post()).statusCode).toBe(200);
  });
  it('rejects false provenance hashes instead of retaining contradictory source evidence', async () => {
    const f = fixture();
    const original = f.dependencies.receiverProvider.assess;
    f.dependencies.receiverProvider.assess = async input => {
      const evidence = await original(input);
      evidence.observations[0]!.raw_hash = '99'.repeat(32);
      return evidence;
    };
    const result = await f.post();
    expect(result.statusCode).toBe(503);
    expect(result.json().permit).toBeNull();
    expect(f.signCount).toBe(0);
  });
  it('does not renew expired checks and preserves authorization after process restart', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'guard-restart-'));
    cleanups.push(() => rmSync(directory, { recursive: true, force: true }));
    const path = join(directory, 'guard.sqlite');
    const f = fixture({ path });
    const first = await allow(f);
    const secondStore = new GuardStore(path);
    cleanups.push(() => secondStore.close());
    const second = new AssessmentService({ ...f.dependencies, store: secondStore });
    expect(await second.assess(registrations[0]!, f.request)).toEqual(first);
    f.advance(120_001);
    f.fresh();
    const expired = await f.post();
    expect(expired.statusCode).toBe(409);
    expect(expired.json().error.code).toBe('CHECK_EXPIRED');
    expect(f.signCount).toBe(1);
  });
  it('serializes concurrent requests and survives interrupted leases with the same nonce', async () => {
    const f = fixture();
    let unblock!: () => void;
    const blocked = new Promise<void>(resolve => { unblock = resolve; });
    f.setSignHook(() => blocked);
    const first = f.post();
    const firstPromise = first.then(response => response);
    await new Promise(resolve => setTimeout(resolve, 15));
    const pending = await f.post();
    expect(pending.statusCode).toBe(409);
    expect(pending.json().error.code).toBe('ISSUANCE_IN_PROGRESS');
    unblock();
    const result = await firstPromise;
    expect(result.statusCode).toBe(200);
    expect(f.signCount).toBe(1);
    const request = { ...f.request, request_id: 'crash-before-sign' };
    const abandoned = f.store.claim(registrations[0]!, request, 'fixture', initialNow);
    f.advance(30_001);
    f.fresh();
    const recovered = await f.post(request);
    expect(recovered.statusCode).toBe(200);
    expect(recovered.json().permit.payload.nonce).toBe(abandoned.nonce);
  });
  it('uses the latest same-revision risk snapshot rather than an earlier allow result', async () => {
    const f = fixture();
    let reads = 0;
    const original = f.dependencies.reputationProvider.getReputation;
    f.dependencies.reputationProvider.getReputation = async () => {
      const snapshot = await original();
      reads++;
      return { ...snapshot, unresolved_report_weight: reads >= 2 ? 10 : 0 };
    };
    const response = await f.post();
    expect(response.statusCode).toBe(200);
    expect(response.json().decision).toBe('warn');
    expect(response.json().permit.payload.verdict).toBe('warn');
    const evidence = (await f.get(`/v1/checks/${response.json().check_id}/evidence`)).json();
    expect(evidence.snapshot.reputation.unresolved_report_weight).toBe(10);
    expect(evidence.evidence_snapshot_hash).toBe(response.json().permit.payload.evidence_snapshot_hash);
  });
  it('keeps historical provenance immutable after newer observations and denies other agents', async () => {
    const f = fixture();
    const first = await allow(f);
    f.setEvidence({ code_identity: 'code-v2' });
    const second = await f.post({ ...f.request, request_id: 'new-observation' });
    expect(second.statusCode).toBe(200);
    const oldSnapshot = await f.get(`/v1/checks/${first.check_id}/evidence`);
    expect(oldSnapshot.json().snapshot.evidence.code_identity).toBe('code-v1');
    expect((await f.get(`/v1/checks/${second.json().check_id}/evidence`)).json().snapshot.evidence.code_identity).toBe('code-v2');
    expect((await f.get(`/v1/checks/${first.check_id}/evidence`, otherToken)).statusCode).toBe(404);
  });
  it('allows only the current claim owner to finish after a stalled signer loses its lease', async () => {
    const f = fixture();
    let unblock!: () => void;
    const blocked = new Promise<void>(resolve => { unblock = resolve; });
    f.setSignHook(() => blocked);
    const first = f.post().then(response => response);
    await new Promise(resolve => setTimeout(resolve, 10));
    const row = f.store.database.prepare('SELECT nonce FROM checks').get() as { nonce: string };
    f.advance(30_001);
    f.fresh();
    f.setSignHook(async () => {});
    const winner = await f.post();
    expect(winner.statusCode).toBe(200);
    expect(winner.json().permit.payload.nonce).toBe(row.nonce);
    unblock();
    expect((await first).statusCode).toBe(409);
    expect((await f.post()).json()).toEqual(winner.json());
    expect(f.store.database.prepare('SELECT COUNT(*) AS n FROM permit_records').get()).toEqual({ n: 1 });
  });
  it('rejects local invalidation or changed authority while the signer is awaited', async () => {
    for (const change of ['local-invalidation', 'policy-pause', 'review-block'] as const) {
      const f = fixture();
      f.setSignHook(async () => {
        if (change === 'local-invalidation') f.store.invalidateReceiver('sandbox', 'receiver.testnet', 'Independent review changed during signing');
        if (change === 'policy-pause') f.setPolicy({ paused: true, revision: '2' });
        if (change === 'review-block') f.setReputation({ blocklist_revision: '2', active_blocks: [{ id: 'new-review', network: 'sandbox', account_id: 'receiver.testnet', code_identity: null, expires_at: initialNow + 300_000, reviewed_by: 'reviewer', evidence_refs: ['fixture:new-review'] }] });
      });
      const response = await f.post();
      expect(response.statusCode).toBe(change === 'local-invalidation' ? 409 : 503);
      expect(response.json().permit).toBeNull();
      expect(f.store.database.prepare('SELECT COUNT(*) AS n FROM permit_records').get()).toEqual({ n: 0 });
    }
  });
  it('rejects a trusted signer that mutates the input action before signing it', async () => {
    const f = fixture();
    const app = createApp({ ...f.dependencies, signPermit(payload) {
      payload.action.receiver_id = 'other-receiver.testnet';
      return signPermit(payload, keys.privateKey);
    } });
    cleanups.push(() => app.close());
    const response = await app.inject({ method: 'POST', url: '/v1/checks', headers: { authorization: `Bearer ${token}` }, payload: f.request });
    expect(response.statusCode).toBe(500);
    expect(response.json().permit).toBeNull();
    expect(f.store.database.prepare('SELECT COUNT(*) AS n FROM permit_records').get()).toEqual({ n: 0 });
    expect((await f.post()).json().permit.payload.action.receiver_id).toBe('receiver.testnet');
  });
  it('does not return a permit if evidence persistence fails', async () => {
    const f = fixture();
    f.store.database.exec("CREATE TRIGGER reject_snapshot BEFORE INSERT ON evidence_snapshots BEGIN SELECT RAISE(ABORT, 'disk unavailable'); END");
    const failed = await f.post();
    expect(failed.statusCode).toBe(503);
    expect(failed.json().permit).toBeNull();
    expect(f.store.database.prepare('SELECT COUNT(*) AS n FROM permit_records').get()).toEqual({ n: 0 });
    f.store.database.exec('DROP TRIGGER reject_snapshot');
    expect((await f.post()).statusCode).toBe(200);
  });
  it('rejects unsupported methods, malformed arguments, overflow amounts and browser-supplied identity', async () => {
    const f = fixture();
    const call = { kind: 'contract_call', receiver_id: 'receiver.testnet', method_name: 'other', args_base64: Buffer.from('{"memo":"hello"}').toString('base64'), attached_deposit_yocto: '0', gas_tgas: 20 };
    expect((await f.post({ ...f.request, request_id: 'call', action: call })).statusCode).toBe(403);
    expect((await f.post({ ...f.request, request_id: 'overflow', action: { ...f.request.action, amount_yocto: (1n << 128n).toString() } })).statusCode).toBe(400);
    expect(f.signCount).toBe(0);
  });
});

describe('revalidation and trusted finalized history', () => {
  it('refreshes critical sources without extending expiry for unchanged security facts', async () => {
    const f = fixture();
    const first = await allow(f);
    f.advance(20_000);
    f.fresh();
    f.setReputation({ coverage: { ...complete, window_start_ms: initialNow - 700000, window_end_ms: initialNow + 20000 } });
    const fresh = await f.revalidate(first.check_id);
    expect(fresh.statusCode).toBe(200);
    expect(fresh.json()).toMatchObject({ status: 'valid', expires_at: first.expires_at });
    expect(f.refreshCount).toBe(1);
    expect(f.signCount).toBe(1);
  });
  it('invalidates code, review revision and same-revision policy/risk changes', async () => {
    for (const change of ['code', 'revision', 'policy', 'risk'] as const) {
      const f = fixture();
      const first = await allow(f);
      if (change === 'code') f.setEvidence({ code_identity: 'code-v2' });
      if (change === 'revision') f.setReputation({ blocklist_revision: '2' });
      if (change === 'policy') f.setPolicy({ max_action_yocto: '99999999999999999999999' });
      if (change === 'risk') f.setReputation({ unresolved_report_weight: 1 });
      expect((await f.revalidate(first.check_id)).json().status).toBe('invalidated');
      expect((await f.post()).json().error.code).toBe('CHECK_INVALIDATED');
      expect(f.signCount).toBe(1);
    }
  });
  it('rereads local invalidation and execution state after awaited revalidation sources', async () => {
    for (const change of ['invalidate', 'submit'] as const) {
      const f = fixture();
      const first = await allow(f);
      const assess = f.dependencies.receiverProvider.assess;
      f.dependencies.receiverProvider.assess = async input => {
        const evidence = await assess(input);
        if (input.refresh) {
          if (change === 'invalidate') f.store.invalidateReceiver('sandbox', 'receiver.testnet', 'Review updated during revalidation');
          else f.store.reconcile({ execution_id: first.check_id, check_id: first.check_id, network: 'sandbox', vault_id: 'vault.testnet', permit_hash: first.permit.permit_hash, state: 'submitted', transaction_id: 'fixture-inflight', receipt_id: null, block_height: null, block_hash: null, observed_at: initialNow + 1, finalized: false, nonexecution_proven: false, owner_approval_ref: null });
        }
        return evidence;
      };
      expect((await f.revalidate(first.check_id)).json().status).toBe(change === 'invalidate' ? 'invalidated' : 'in_flight');
    }
  });
  it('keeps unavailable revalidation fail-closed rather than reporting valid', async () => {
    const f = fixture();
    const first = await allow(f);
    f.setUnavailable(true);
    const result = await f.revalidate(first.check_id);
    expect(result.statusCode).toBe(503);
    expect(result.json().permit).toBeNull();
    expect(f.signCount).toBe(1);
  });
  it('keeps uncertain attempts out of success credit; reconciles final receipts idempotently', async () => {
    const f = fixture();
    const first = await allow(f);
    const observation: ExecutionObservation = { execution_id: first.check_id, check_id: first.check_id, network: 'sandbox', vault_id: 'vault.testnet', permit_hash: first.permit.permit_hash, state: 'pending', transaction_id: 'fixture-transaction', receipt_id: 'fixture-receipt', block_height: null, block_hash: null, observed_at: initialNow + 10, finalized: false, nonexecution_proven: false, owner_approval_ref: null };
    f.store.reconcile(observation);
    expect(f.store.history(registrations[0]!, 'receiver.testnet', 'fixture').finalized_successes).toBe(0);
    f.store.reconcile({ ...observation, state: 'uncertain', observed_at: initialNow + 20 });
    expect((await f.revalidate(first.check_id)).json().status).toBe('in_flight');
    const final: ExecutionObservation = { ...observation, state: 'succeeded', finalized: true, block_hash: 'fixture-final-block', block_height: '11', observed_at: initialNow + 30 };
    f.store.reconcile(final);
    f.store.reconcile({ ...final, observed_at: initialNow + 40 });
    f.store.reconcile({ ...observation, observed_at: initialNow + 50 });
    expect(f.store.history(registrations[0]!, 'receiver.testnet', 'fixture')).toEqual({ finalized_successes: 1, approved_code_identity: 'code-v1' });
    expect((await f.get(`/v1/executions/${first.check_id}`)).json().stage).toBe('succeeded');
    expect(f.store.database.prepare('SELECT COUNT(*) AS n FROM execution_receipts').get()).toEqual({ n: 1 });
    expect((await f.revalidate(first.check_id)).json().status).toBe('consumed');
    expect(() => f.store.reconcile({ ...final, state: 'failed', nonexecution_proven: true })).toThrow();
    expect(() => f.store.reconcile({ ...final, permit_hash: '99'.repeat(32) })).toThrow();
  });
  it('requires final receipt/nonexecution proof and separate owner evidence for warned successes', async () => {
    const f = fixture();
    f.setEvidence({ account_age_days: null });
    const first = (await f.post()).json();
    const observation: ExecutionObservation = { execution_id: first.check_id, check_id: first.check_id, network: 'sandbox', vault_id: 'vault.testnet', permit_hash: first.permit.permit_hash, state: 'failed', transaction_id: 'fixture-transaction', receipt_id: 'fixture-receipt', block_height: '11', block_hash: 'fixture-final-block', observed_at: initialNow + 1, finalized: true, nonexecution_proven: false, owner_approval_ref: null };
    expect(() => f.store.reconcile(observation)).toThrow();
    expect(() => f.store.reconcile({ ...observation, state: 'succeeded' })).toThrow();
    f.store.reconcile({ ...observation, state: 'succeeded', owner_approval_ref: 'fixture-owner-approval' });
    expect(f.store.history(registrations[0]!, 'receiver.testnet', 'fixture').finalized_successes).toBe(1);
    expect((await f.app.inject({ method: 'POST', url: `/v1/executions/${first.check_id}`, headers: { authorization: `Bearer ${token}` }, payload: { succeeded: true } })).statusCode).toBe(404);
  });
});

describe('finalized code identity history', () => {
  it('issues a warning for first deployment after a finalized code-free payment', async () => {
    const f = fixture();
    f.setEvidence({ code_identity: null });
    const first = checkResponseSchema.parse((await f.post()).json());
    expect(first.decision).toBe('allow');
    finalize(f, first, '10', initialNow + 1);
    f.setEvidence({ code_identity: 'code-v1', recent_deployment: false });
    const deployed = checkResponseSchema.parse((await f.post({ ...f.request, request_id: 'first-deployment' })).json());
    expect(deployed.decision).toBe('warn');
    expect(deployed.reason_codes).toContain('CODE_CHANGED');
    expect(deployed.permit?.payload.verdict).toBe('warn');
  });
  it.each([
    ['9', '10', '11'],
    ['9007199254740991', '9007199254740992', '9007199254740993'],
    ['18446744073709551613', '18446744073709551614', '18446744073709551615'],
  ])('keeps the latest approved code after delayed older receipts at %s / %s / %s', async (firstHeight, delayedHeight, latestHeight) => {
    const f = fixture();
    const request = { ...f.request, action: { kind: 'contract_call', receiver_id: 'receiver.testnet', method_name: 'accept_memo', args_base64: Buffer.from('{"memo":"history regression"}').toString('base64'), attached_deposit_yocto: '0', gas_tgas: 30 } };
    const account = (await f.dependencies.receiverProvider.assess({})).observations[0]!;
    f.setEvidence({ observations: [account, { ...account, id: 'fixture:code', kind: 'contract_code' }] });
    const first = checkResponseSchema.parse((await f.post(request)).json());
    const delayed = checkResponseSchema.parse((await f.post({ ...request, request_id: 'delayed-v1' })).json());
    finalize(f, first, firstHeight, initialNow + 1);
    f.setEvidence({ code_identity: 'code-v2' });
    const upgraded = checkResponseSchema.parse((await f.post({ ...request, request_id: 'upgrade-v2' })).json());
    expect(upgraded.decision).toBe('warn');
    finalize(f, upgraded, latestHeight, initialNow + 2);
    const olderReceipt = finalize(f, delayed, delayedHeight, initialNow + 3);
    f.store.reconcile({ ...olderReceipt, observed_at: initialNow + 4 });
    expect(f.store.history(registrations[0]!, 'receiver.testnet', 'fixture')).toEqual({ finalized_successes: 3, approved_code_identity: 'code-v2' });
    expect(f.store.execution(delayed.check_id, registrations[0]!.agent_id)?.finalized_block_height).toBe(delayedHeight);
    f.setEvidence({ code_identity: 'code-v1' });
    const rollback = checkResponseSchema.parse((await f.post({ ...request, request_id: 'rollback-v1' })).json());
    expect(rollback.decision).toBe('warn');
    expect(rollback.reason_codes).toContain('CODE_CHANGED');
    expect(rollback.permit?.payload.verdict).toBe('warn');
  });
  it('requires a warning for conflicting code identities finalized in the same block', async () => {
    const f = fixture();
    f.setEvidence({ code_identity: null });
    const first = checkResponseSchema.parse((await f.post()).json());
    finalize(f, first, '10', initialNow + 1);
    f.setEvidence({ code_identity: 'code-v2' });
    const second = checkResponseSchema.parse((await f.post({ ...f.request, request_id: 'same-block-v2' })).json());
    finalize(f, second, '10', initialNow + 2);
    expect(f.store.history(registrations[0]!, 'receiver.testnet', 'fixture').code_identity_ambiguous).toBe(true);
    for (const identity of [null, 'code-v2']) {
      f.setEvidence({ code_identity: identity });
      const next = checkResponseSchema.parse((await f.post({ ...f.request, request_id: `ambiguous-${identity}` })).json());
      expect(next.decision).toBe('warn');
      expect(next.reason_codes).toContain('CODE_CHANGED');
    }
    const third = checkResponseSchema.parse((await f.post({ ...f.request, request_id: 'later-block-v2' })).json());
    finalize(f, third, '11', initialNow + 3);
    expect(f.store.history(registrations[0]!, 'receiver.testnet', 'fixture')).toEqual({ finalized_successes: 3, approved_code_identity: 'code-v2' });
  });
  it('allows unchanged code when multiple successes share one finalized block', async () => {
    const f = fixture();
    const first = checkResponseSchema.parse((await f.post()).json());
    const second = checkResponseSchema.parse((await f.post({ ...f.request, request_id: 'same-code' })).json());
    finalize(f, first, '10', initialNow + 2);
    finalize(f, second, '10', initialNow + 1);
    expect(f.store.history(registrations[0]!, 'receiver.testnet', 'fixture')).toEqual({ finalized_successes: 2, approved_code_identity: 'code-v1' });
    expect(checkResponseSchema.parse((await f.post({ ...f.request, request_id: 'unchanged-code' })).json()).decision).toBe('allow');
  });
  it('issues no permit when a legacy finalized success has no retained execution height', async () => {
    const f = fixture();
    const first = checkResponseSchema.parse((await f.post()).json());
    finalize(f, first, '10', initialNow + 1);
    f.store.database.prepare('UPDATE executions SET finalized_block_height=NULL WHERE id=?').run(first.check_id);
    const response = await f.post({ ...f.request, request_id: 'missing-chronology' });
    expect(response.statusCode).toBe(503);
    expect(response.json().permit).toBeNull();
    expect(f.signCount).toBe(1);
  });
  it('backfills existing finalized receipts and preserves chronology after restart', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'guard-history-upgrade-'));
    cleanups.push(() => rmSync(directory, { recursive: true, force: true }));
    const path = join(directory, 'guard.sqlite');
    const f = fixture({ path });
    const first = checkResponseSchema.parse((await f.post()).json());
    const delayed = checkResponseSchema.parse((await f.post({ ...f.request, request_id: 'legacy-delayed' })).json());
    finalize(f, first, '10', initialNow + 1);
    f.setEvidence({ code_identity: 'code-v2' });
    const second = checkResponseSchema.parse((await f.post({ ...f.request, request_id: 'legacy-v2' })).json());
    finalize(f, second, '20', initialNow + 2);
    finalize(f, delayed, '11', initialNow + 3);
    const originalSnapshot = f.store.check(first.check_id, registrations[0]!.agent_id)?.snapshot;
    // Reconstruct the previous schema while retaining actual issued checks/receipts.
    f.store.database.exec("DROP INDEX executions_history_height; ALTER TABLE executions DROP COLUMN finalized_block_height; DELETE FROM schema_migrations WHERE id='core-002'");
    const upgraded = new GuardStore(path);
    cleanups.push(() => upgraded.close());
    expect(upgraded.history(registrations[0]!, 'receiver.testnet', 'fixture')).toEqual({ finalized_successes: 3, approved_code_identity: 'code-v2' });
    expect(upgraded.check(first.check_id, registrations[0]!.agent_id)?.snapshot).toEqual(originalSnapshot);
    expect(upgraded.execution(delayed.check_id, registrations[0]!.agent_id)?.finalized_block_height).toBe('11');
  });
});

describe('migration and transport boundaries', () => {
  it('refuses changed or reordered applied migrations', () => {
    const directory = mkdtempSync(join(tmpdir(), 'guard-migrations-'));
    cleanups.push(() => rmSync(directory, { recursive: true, force: true }));
    mkdirSync(join(directory, 'core'));
    const original = readFileSync(new URL('../../db/core/001_initial.sql', import.meta.url), 'utf8');
    writeFileSync(join(directory, 'core/001.sql'), original);
    const manifestPath = join(directory, 'migrations.json');
    writeFileSync(manifestPath, JSON.stringify({ version: 1, migrations: [{ id: 'core-001', path: 'core/001.sql' }] }));
    const path = join(directory, 'test.sqlite');
    const store = new GuardStore(path, { manifestPath });
    store.close();
    writeFileSync(join(directory, 'core/001.sql'), original + '\n-- changed after application\n');
    expect(() => new GuardStore(path, { manifestPath })).toThrow('Applied migration changed');
  });
  it('does not give report reviewer authority to agent credentials and sanitizes health', async () => {
    const f = fixture({ reportPlugin(app, context) {
      app.post('/v1/review-test', async request => context.authenticateReviewer(request));
    } });
    expect((await f.app.inject({ method: 'POST', url: '/v1/review-test', headers: { authorization: `Bearer ${token}` } })).statusCode).toBe(403);
    const health = await f.app.inject({ method: 'GET', url: '/health' });
    expect(health.statusCode).toBe(200);
    expect(health.body).not.toContain(token);
    expect(health.body).not.toContain('credential_hash');
    expect(health.json().reports).toBe('configured');
  });
  it('enforces reviewer credential separation even for later registrations', async () => {
    const f = fixture();
    const reviewerToken = 'independent-reviewer-credential-0001';
    const plugin: NonNullable<Parameters<typeof createApp>[0]['reportPlugin']> = (app, context) => {
      app.post('/v1/reviewer-authority', async request => context.authenticateReviewer(request));
    };
    const misconfigured = createApp({ ...f.dependencies, reviewerCredentialHash: credentialHash(token), reportPlugin: plugin });
    const separate = createApp({ ...f.dependencies, reviewerCredentialHash: credentialHash(reviewerToken), reportPlugin: plugin });
    cleanups.push(() => misconfigured.close(), () => separate.close());
    const request = (app: typeof separate, credential: string) => app.inject({ method: 'POST', url: '/v1/reviewer-authority', headers: { authorization: `Bearer ${credential}` } });
    expect((await request(misconfigured, token)).statusCode).toBe(403);
    expect((await request(separate, reviewerToken)).statusCode).toBe(200);
    f.store.registerAgent({ ...registrations[0]!, agent_id: 'later-agent', credential_hash: credentialHash(reviewerToken) });
    expect((await request(separate, reviewerToken)).statusCode).toBe(403);
  });
  it('bounds body size and rate-limit state', async () => {
    const f = fixture();
    const large = await f.post({ ...f.request, junk: 'x'.repeat(20_000) });
    expect(large.statusCode).toBe(413);
    const limited = createApp({ ...f.dependencies, rateLimit: { max: 1, windowMs: 1000 } });
    cleanups.push(() => limited.close());
    const headers = { authorization: `Bearer ${token}` };
    expect((await limited.inject({ method: 'POST', url: '/v1/checks', headers, payload: f.request })).statusCode).toBe(200);
    expect((await limited.inject({ method: 'POST', url: '/v1/checks', headers, payload: f.request })).statusCode).toBe(429);
  });
});
