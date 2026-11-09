import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { generateKeyPair, signReportPayload, signPermit, publicKeyFromKeyObject, type ReportRecord, type ReceiverEvidence } from '@counterparty-guard/shared';
import { ReportRepository, createReputationProvider, clusterDependenceGroups, getReceiverReputation, FaucetRegistry, traverseBoundedGraph, InMemoryGraphProvider } from '@counterparty-guard/reputation';
import { createApp } from '../../apps/api/src/app.js';
import { createReportsPlugin } from '../../apps/api/src/routes/reports.js';
import { GuardStore, credentialHash, digest } from '../../apps/api/src/storage/store.js';
import { extractReviewerContext } from '../../apps/api/src/auth/reviewer-auth.js';
import type { FastifyRequest } from 'fastify';

const cleanups: (() => Promise<unknown> | void)[] = [];
afterEach(async () => { for (const close of cleanups.splice(0).reverse()) await close(); });
const now = 1800000000000;
const agentToken = 'fixture-agent-private-credential';
const reviewerToken = 'fixture-independent-reviewer-credential';
function fixture() {
  const store = new GuardStore(); cleanups.push(() => store.close());
  const repository = new ReportRepository(store.database, () => now);
  const scorer = generateKeyPairSync('ed25519');
  const agent = { agent_id: 'agent', account_id: 'agent.testnet', public_key: publicKeyFromKeyObject(generateKeyPairSync('ed25519').publicKey), credential_hash: credentialHash(agentToken), network: 'sandbox' as const, vault_id: 'vault.testnet' };
  store.registerAgent(agent);
  const coverage = { complete: true, truncated: false, pages: 1, window_start_ms: null, window_end_ms: null, notes: [] };
  const app = createApp({ store, sourceMode: 'fixture', clock: () => now, scorerPublicKey: publicKeyFromKeyObject(scorer.publicKey), signPermit: payload => signPermit(payload, scorer.privateKey),
    reviewerCredentialHash: credentialHash(reviewerToken), reputationProvider: createReputationProvider(repository, () => now), reportPlugin: createReportsPlugin({ now: () => now }),
    receiverProvider: { sourceMode: 'fixture', async assess(input) {
      const value = { fixture: true };
      const evidence: ReceiverEvidence = { network: input.network, source_mode: 'fixture', account_id: input.account_id, exists: true, code_identity: 'code-v1', account_age_days: 100, recent_deployment: false, independent_successful_counterparties: 15, transfer_count: 10, activity_manipulation_score: 0, coverage, observed_at: now,
        observations: [{ id: 'fixture-account', kind: 'account_state', network: input.network, source_mode: 'fixture', source: 'fixture', fetched_at: now, source_timestamp: now, block_height: '1', block_hash: 'fixture-block', coverage, raw_hash: digest(value), value }] };
      return evidence;
    } },
    policyProvider: { async getPolicy() { return { network: 'sandbox', vault_id: 'vault.testnet', deployment_instance_id: '11'.repeat(32), revision: '1', observed_at: now, paused: false, max_action_yocto: '100000000000000000000000', permit_ttl_ms: 120000, max_source_age_ms: 60000, supported_call: null }; } },
  });
  cleanups.push(() => app.close());
  const check = (requestId: string, receiver = 'receiver.testnet') => app.inject({ method: 'POST', url: '/v1/checks', headers: { authorization: `Bearer ${agentToken}` }, payload: { schema_version: 1, network: 'sandbox', vault_id: 'vault.testnet', request_id: requestId, action: { kind: 'transfer_near', receiver_id: receiver, amount_yocto: '1' } } });
  const review = (id: string, decision = 'active_block', token = reviewerToken, scope = 'account') => app.inject({ method: 'POST', url: `/v1/reports/${id}/review`, headers: { authorization: `Bearer ${token}`, 'x-reviewer-id': 'forged-reviewer' }, payload: { decision, scope, reason: 'Reviewed synthetic fixture evidence only.' } });
  const submit = async (receiver = 'receiver.testnet', codeHash?: string) => {
    const key = generateKeyPair();
    const payload = { network: 'sandbox' as const, accused_account_id: receiver, reporter_id: `reporter-${randomUUID()}.testnet`, reporter_public_key: key.publicKey, category: 'other' as const, description: 'Synthetic signed allegation for a regression.', transaction_references: ['fixture:reference:001'], evidence_content_hashes: [], contract_code_hash: codeHash ?? null, issued_at: now, expires_at: now + 86400000, nonce: randomUUID() };
    const response = await app.inject({ method: 'POST', url: '/v1/reports', payload: { ...payload, signature: signReportPayload(payload, key.secretKey) } });
    expect(response.statusCode, response.body).toBe(201);
    return response.json().report_id as string;
  };
  return { store, repository, app, check, review, submit };
}
function report(id: string, reference: string): ReportRecord {
  return { report_id: randomUUID(), network: 'sandbox', accused_account_id: 'receiver.testnet', reporter_id: id, reporter_public_key: `fixture-key-${id}`, category: 'other', description: 'Synthetic fixture allegation.', transaction_references: [reference], evidence_content_hashes: [], contract_code_hash: null, status: 'submitted', issued_at: now, expires_at: now + 86400000, nonce: randomUUID(), signature: 'fixture-not-used-for-intake', created_at: now };
}
describe('A+C shared authorization and review boundaries', () => {
  it('requires configured credentials and never accepts prefix credentials or caller audit identity', async () => {
    const request = { headers: { authorization: 'Bearer reviewer-invented', 'x-reviewer-id': 'forged' } } as unknown as FastifyRequest;
    expect(extractReviewerContext(request).authenticated).toBe(false);
    expect(extractReviewerContext(request, { credentials: [{ token: 'reviewer-invented', reviewer_id: 'trusted-reviewer', role: 'reviewer' }] }).reviewer_id).toBe('trusted-reviewer');
    const f = fixture(); const id = await f.submit();
    for (const token of ['reviewer-invented-credential', 'admin-invented-credential', agentToken]) expect((await f.review(id, 'active_block', token)).statusCode).toBe(403);
    expect((await f.review(id)).statusCode).toBe(200);
    expect(f.repository.getReviewsByReport(id)[0]?.reviewer_id).toBe('configured-reviewer');
  });
  it.each(['rejected','dismissed'])('review blocks new checks and corrective %s revokes with a new revision', async correctionDecision => {
    const f = fixture(); const allowed = (await f.check('before')).json(); expect(allowed.decision).toBe('allow');
    const id = await f.submit(); const activation = await f.review(id); expect(activation.statusCode).toBe(200);
    expect((await f.check('before')).statusCode).toBe(409);
    const blocked = (await f.check('after-block')).json(); expect(blocked.decision).toBe('block'); expect(blocked.permit).toBeNull();
    const correction = await f.review(id, correctionDecision); expect(correction.statusCode).toBe(200);
    expect(correction.json().blocklist_revision).toBeGreaterThan(activation.json().blocklist_revision);
    expect((await f.check('after-correction')).json().decision).toBe('allow');
    expect(f.repository.getReviewsByReport(id)).toHaveLength(2);
  });
  it('keeps code-scoped blocks on the reviewed account and code', async () => {
    const f = fixture(); const id = await f.submit('alice.testnet', 'code-v1'); expect((await f.review(id, 'active_block', reviewerToken, 'code_hash')).statusCode).toBe(200);
    expect((await f.check('alice', 'alice.testnet')).json().decision).toBe('block');
    expect((await f.check('bob', 'bob.testnet')).json().decision).toBe('allow');
    expect(f.repository.getActiveBlock('sandbox', 'alice.testnet', 'code-v2')).toBeNull();
  });
  it('allows authenticated block revocation after the originating report becomes terminal', async () => {
    const f = fixture(); const id = await f.submit(); await f.review(id);
    const block = f.repository.getActiveBlocks('sandbox', 'receiver.testnet', now)[0]!;
    f.repository.updateReportStatus(id, 'expired');
    const path = `/v1/blocklist/${block.entry_id}/revoke`;
    expect((await f.app.inject({ method: 'POST', url: path, headers: { authorization: `Bearer ${agentToken}` }, payload: { reason: 'Independent correction after expiry' } })).statusCode).toBe(403);
    const response = await f.app.inject({ method: 'POST', url: path, headers: { authorization: `Bearer ${reviewerToken}` }, payload: { reason: 'Independent correction after expiry' } });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.json().blocklist_revision).toBeGreaterThan(1);
    expect(f.repository.getActiveBlocks('sandbox', 'receiver.testnet', now)).toHaveLength(0);
    expect((await f.check('after-expired-report-revocation')).json().decision).toBe('allow');
  });
  it('rolls back block/revision changes if the audit write fails', async () => {
    const f = fixture(); const id = await f.submit();
    f.store.database.exec("CREATE TRIGGER fail_review BEFORE INSERT ON report_reviews BEGIN SELECT RAISE(ABORT,'fixture failure'); END");
    expect((await f.review(id)).statusCode).toBe(503);
    expect(f.repository.getLatestBlocklistRevision()).toBe(0);
    expect(f.repository.getActiveBlocks('sandbox', 'receiver.testnet', now)).toHaveLength(0);
    expect(f.repository.getReport(id)?.status).toBe('submitted');
  });
  it('deduplicates shared evidence across identities but preserves diverse evidence from common-funder users', () => {
    const a = report('alice.testnet', 'fixture:event:one'); const b = report('bob.testnet', 'fixture:event:two');
    const lineages = new Map([a,b].map(item => [item.reporter_id, { reporterId: item.reporter_id, directFunderId: 'exchange.testnet', allInboundFunders: ['exchange.testnet'], transferPeers: [] as string[] }]));
    expect(clusterDependenceGroups({ network: 'sandbox', reports: [a,b], lineages }).totalEffectiveWeight).toBe(2);
    const duplicated = { ...b, transaction_references: a.transaction_references };
    expect(clusterDependenceGroups({ network: 'sandbox', reports: [a,duplicated], lineages }).totalEffectiveWeight).toBe(1);
    lineages.get(a.reporter_id)!.transferPeers = [b.reporter_id];
    expect(clusterDependenceGroups({ network: 'sandbox', reports: [a,b], lineages }).totalEffectiveWeight).toBe(1);
  });
  it('a faucet exemption cannot erase an independent code-change condition', async () => {
    const f = fixture(); const allegation = report('alice.testnet', 'fixture:event:one');
    f.repository.registerReporter({ reporter_id: allegation.reporter_id, public_key: allegation.reporter_public_key, network: 'sandbox' }); f.repository.insertReport(allegation);

    const graph = await traverseBoundedGraph(new InMemoryGraphProvider([{ id: 'fixture-edge', source: 'faucet.testnet', target: allegation.reporter_id, type: 'transfer', timestamp: now - 1, amountYocto: '1' },{ id: 'fixture-receiver-edge', source: allegation.reporter_id, target: 'receiver.testnet', type: 'transfer', timestamp: now - 1, amountYocto: '1' }]), 'receiver.testnet', 'sandbox', { asOfTimestamp: now });
    const faucetRegistry = new FaucetRegistry(undefined, { loadDefaults: false });
    faucetRegistry.addExemption({ exemptionId: 'synthetic-faucet', faucetAccountId: 'faucet.testnet', network: 'sandbox', label: 'Synthetic faucet', exemptionType: 'faucet', isActive: true });
    const result = await getReceiverReputation({ faucetRegistry, network: 'sandbox', accountId: 'receiver.testnet', repository: f.repository, subgraph: graph, now, priorApprovedCodeHash: 'old-code', contractCodeHash: 'new-code' });
    expect(result.reasonCodes).toContain('CODE_CHANGED'); expect(result.reputationRiskPoints).toBeGreaterThanOrEqual(30);
  });
});
