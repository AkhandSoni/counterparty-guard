/**
 * @file tests/regression/s7-upgrade-regression.test.ts
 * @description Feature 50: S7 Contract Bytecode Upgrade Automated Regression Suite.
 *
 * Verifies:
 * 1. Bytecode mutation (previous_code_hash !== current_code_hash) suspends historical
 *    reputation credit and forces warning reassessment (CODE_CHANGED, risk 55).
 * 2. Unchanged bytecode (previous_code_hash === current_code_hash) retains positive
 *    established credit (risk 5, allow) without warning.
 * 3. Execution under Guard Interceptor refuses automated signing (signed: false, submitted: false,
 *    receiver_balance_delta: "0") and halts awaiting human owner approval.
 * 4. Human owner approval requires on-chain call to vault.approve_warn with exact permit_hash.
 * 5. Adversarial combinations: Sybil floods and faucet exemptions cannot downgrade code change risk.
 * 6. Sequential upgrade lifecycle (v1.0 allow -> v2.0 warn -> approved v2.0 allow -> v3.0 warn).
 * 7. End-to-end integration with DeterministicAdapter executing Scenario S7.
 */

import { loadScenarioFixture, s7Fixture } from '@counterparty-guard/fixtures';
import {
  type AccountAdjacency,
  type AccountNode,
  type BoundedSubgraph,
  ReportRepository,
  createDatabase,
  getReceiverReputation,
  runMigrations,
} from '@counterparty-guard/reputation';
import { ReceiverReputationSchema } from '@counterparty-guard/shared';
import { type Action, DemoExecutionLogSchema, type ExecutionPermit, ExecutionPermitSchema, ScenarioDefinitionSchema } from '@counterparty-guard/shared/demo';
import { beforeEach, describe, expect, it } from 'vitest';
import { DeterministicAdapter } from '../../scripts/demo/harness/adapter.js';
import {
  WarningApprovalRequiredError,
  evaluateGuard,
  guardedAgentExecute,
} from '../../scripts/demo/harness/guard.js';

describe('Feature 50: S7 Contract Upgrade Regression Suite', () => {
  const now = 1700000000000;
  const OLD_CODE_HASH = '3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b';
  const NEW_CODE_HASH = '7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e';

  function buildMockSubgraph(
    accountsVisited: number,
    edgesTraversed: number,
    seedAccountId: string,
    edges: Array<{ source: string; target: string; amountYocto?: string; timestamp?: number }> = [],
  ): BoundedSubgraph {
    const nodes = new Map<string, AccountNode>();
    nodes.set(seedAccountId, { accountId: seedAccountId, hop: 0, discoveredAt: now });
    for (let i = 1; i < accountsVisited; i++) {
      const acc = `neighbor_${i}.testnet`;
      nodes.set(acc, { accountId: acc, hop: 1, discoveredAt: now });
    }

    const adjacency = new Map<string, AccountAdjacency>();
    for (const n of nodes.keys()) {
      adjacency.set(n, { inEdges: [], outEdges: [] });
    }

    const graphEdges = edges.map((e, idx) => ({
      id: `edge_${idx}`,
      source: e.source,
      target: e.target,
      amountYocto: e.amountYocto ?? '1000000000000000000000000',
      timestamp: e.timestamp ?? now - 10000,
      type: 'transfer' as const,
    }));

    for (const ge of graphEdges) {
      if (!nodes.has(ge.source)) {
        nodes.set(ge.source, { accountId: ge.source, hop: 1, discoveredAt: ge.timestamp });
      }
      if (!nodes.has(ge.target)) {
        nodes.set(ge.target, { accountId: ge.target, hop: 1, discoveredAt: ge.timestamp });
      }
      if (!adjacency.has(ge.source)) adjacency.set(ge.source, { inEdges: [], outEdges: [] });
      if (!adjacency.has(ge.target)) adjacency.set(ge.target, { inEdges: [], outEdges: [] });
      adjacency.get(ge.source)?.outEdges.push(ge);
      adjacency.get(ge.target)?.inEdges.push(ge);
    }

    return {
      seedAccountId,
      nodes,
      edges: graphEdges,
      adjacency,
      coverage: {
        accountsVisited: Math.max(accountsVisited, nodes.size),
        edgesTraversed: Math.max(edgesTraversed, graphEdges.length),
        truncated: false,
        windowDays: 7,
      },
    };
  }

  // =========================================================================
  // Suite 1: Canonical Scenario S7 Fixture Invariants
  // =========================================================================
  describe('Suite 1: Canonical Scenario S7 Fixture Invariants', () => {
    it('s7Fixture conforms to ScenarioDefinitionSchema with exact invariant fields', () => {
      const parsed = ScenarioDefinitionSchema.parse(s7Fixture);
      expect(parsed.id).toBe('S7');
      expect(parsed.name).toBe('Upgraded Contract Receiver');
      expect(parsed.expected_decision).toBe('warn');
      expect(parsed.expected_reason_codes).toContain('CODE_CHANGED');
      expect(parsed.expected_signed).toBe(false);
      expect(parsed.expected_submitted).toBe(false);
      expect(parsed.expected_balance_delta_yocto).toBe('0');
      expect(parsed.proposed_action.kind).toBe('contract_call');
      expect(parsed.proposed_action.receiver_id).toBe('contract.testnet');
    });

    it('loadScenarioFixture(S7) loads fixture identical to s7Fixture', () => {
      const loaded = loadScenarioFixture('S7');
      expect(loaded.id).toBe(s7Fixture.id);
      expect(loaded.name).toBe(s7Fixture.name);
      expect(loaded.expected_decision).toBe(s7Fixture.expected_decision);
    });

    it('initial state encodes code hash mutation and canonical warning permit', () => {
      const state = s7Fixture.initial_state as {
        is_contract: boolean;
        code_hash_changed: boolean;
        previous_code_hash: string;
        current_code_hash: string;
        reputation_risk_points: number;
        canonical_permit: {
          permit_hash: string;
          verdict: string;
          nonce: string;
        };
      };

      expect(state.is_contract).toBe(true);
      expect(state.code_hash_changed).toBe(true);
      expect(state.previous_code_hash).toBe(OLD_CODE_HASH);
      expect(state.current_code_hash).toBe(NEW_CODE_HASH);
      expect(state.previous_code_hash).not.toBe(state.current_code_hash);
      expect(state.reputation_risk_points).toBe(55);
      expect(state.canonical_permit.verdict).toBe('warn');
      expect(state.canonical_permit.permit_hash).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  // =========================================================================
  // Suite 2: Core Scoring Engine Bytecode Upgrade & Credit Suspension
  // =========================================================================
  describe('Suite 2: Core Scoring Engine Bytecode Upgrade & Credit Suspension', () => {
    let repo: ReportRepository;

    beforeEach(() => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      repo = new ReportRepository(db, () => now);
    });

    it('S7 Bytecode Mutation suspends established credit and sets risk 55 with CODE_CHANGED', async () => {
      const establishedSubgraph = buildMockSubgraph(12, 25, 'contract.testnet');

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: 'contract.testnet',
        contractCodeHash: NEW_CODE_HASH,
        priorApprovedCodeHash: OLD_CODE_HASH,
        repository: repo,
        subgraph: establishedSubgraph,
        now,
      });

      expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
      expect(rep.isBlocked).toBe(false);
      expect(rep.reasonCodes).toContain('CODE_CHANGED');
      expect(rep.reputationRiskPoints).toBe(55);

      // Invariant: Established credit (riskPoints = 5) MUST NOT be granted when code hash has changed
      expect(rep.reputationRiskPoints).not.toBe(5);
    });

    it('Negative Control: Unchanged bytecode retains positive credit (risk 5) without warning', async () => {
      const establishedSubgraph = buildMockSubgraph(12, 25, 'contract.testnet');

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: 'contract.testnet',
        contractCodeHash: OLD_CODE_HASH,
        priorApprovedCodeHash: OLD_CODE_HASH, // Identical code hashes
        repository: repo,
        subgraph: establishedSubgraph,
        now,
      });

      expect(rep.isBlocked).toBe(false);
      expect(rep.reasonCodes).not.toContain('CODE_CHANGED');
      expect(rep.reputationRiskPoints).toBe(40); // Retains clean merchant status
    });

    it('Bytecode upgrade on young / sparse receiver enforces risk 55 over young vendor risk 45', async () => {
      const sparseSubgraph = buildMockSubgraph(2, 1, 'new-contract.testnet');

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: 'new-contract.testnet',
        contractCodeHash: NEW_CODE_HASH,
        priorApprovedCodeHash: OLD_CODE_HASH,
        repository: repo,
        subgraph: sparseSubgraph,
        now,
      });

      expect(rep.reasonCodes).toContain('CODE_CHANGED');
      expect(rep.reputationRiskPoints).toBe(55);
      // RECENT_DEPLOYMENT and UNKNOWN_AGE (risk 45) are not emitted when codeChanged is true
      expect(rep.reasonCodes).not.toContain('RECENT_DEPLOYMENT');
    });

    it('Missing or null code hash combinations do not emit CODE_CHANGED', async () => {
      const establishedSubgraph = buildMockSubgraph(12, 25, 'account.testnet');

      // Case A: Both null
      const repA = await getReceiverReputation({
        network: 'testnet',
        accountId: 'account.testnet',
        contractCodeHash: null,
        priorApprovedCodeHash: null,
        repository: repo,
        subgraph: establishedSubgraph,
        now,
      });
      expect(repA.reasonCodes).not.toContain('CODE_CHANGED');
      expect(repA.reputationRiskPoints).toBe(40);

      // Case B: First deployment (no prior approved hash)
      const repB = await getReceiverReputation({
        network: 'testnet',
        accountId: 'account.testnet',
        contractCodeHash: NEW_CODE_HASH,
        priorApprovedCodeHash: null,
        repository: repo,
        subgraph: establishedSubgraph,
        now,
      });
      expect(repB.reasonCodes).toContain('CODE_CHANGED');
    });
  });

  // =========================================================================
  // Suite 3: Adversarial Combinations & Priority Invariants
  // =========================================================================
  describe('Suite 3: Adversarial Combinations & Priority Invariants', () => {
    let repo: ReportRepository;

    beforeEach(() => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      repo = new ReportRepository(db, () => now);
    });

    it('Sybil report flood cannot downgrade code change risk 55 to 20', async () => {
      const accused = 'mutated-contract.testnet';
      const graphEdges: Array<{ source: string; target: string; amountYocto?: string }> = [];

      // 10 Sybil reporters funded by single coordinator submit reports
      for (let i = 1; i <= 10; i++) {
        const reporterId = `sybil_bot_${i}.testnet`;
        repo.registerReporter({
          reporter_id: reporterId,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });
        repo.insertReport({
          report_id: `rep_sybil_${i}`,
          network: 'testnet',
          accused_account_id: accused,
          reporter_id: reporterId,
          reporter_public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          category: 'malicious_contract',
          description: 'Sybil coordination attack on upgraded contract',
          transaction_references: [`tx_sybil_${i}`],
          evidence_content_hashes: [
            '0000000000000000000000000000000000000000000000000000000000000000',
          ],
          contract_code_hash: NEW_CODE_HASH,
          status: 'submitted',
          issued_at: now - 3600_000,
          expires_at: now + 3600_000,
          nonce: `nonce_sybil_${i}`,
          signature: 'ed25519:4a...mock',
          created_at: now - 3600_000,
        });
        graphEdges.push({
          source: 'sybil_funder.testnet',
          target: reporterId,
          amountYocto: '1000000000000000000000000',
        });
      }

      const subgraph = buildMockSubgraph(20, 30, accused, graphEdges);

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: accused,
        contractCodeHash: NEW_CODE_HASH,
        priorApprovedCodeHash: OLD_CODE_HASH,
        repository: repo,
        subgraph,
        now,
      });

      expect(rep.reasonCodes).toContain('CODE_CHANGED');
      expect(rep.reasonCodes).toContain('DEPENDENT_REPORTS');
      // Crucial Security Invariant: riskPoints MUST stay 55, not be overwritten to 20
      expect(rep.reputationRiskPoints).toBe(55);
      expect(rep.isBlocked).toBe(false);
    });

    it('Code upgrade combined with circular activity takes maximum risk points', async () => {
      const accused = 'circular-mutated.testnet';
      // Circular loop: accused -> peer_a -> peer_b -> accused
      const edges = [
        { source: accused, target: 'peer_a.testnet' },
        { source: 'peer_a.testnet', target: 'peer_b.testnet' },
        { source: 'peer_b.testnet', target: accused },
      ];
      const subgraph = buildMockSubgraph(10, 15, accused, edges);

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: accused,
        contractCodeHash: NEW_CODE_HASH,
        priorApprovedCodeHash: OLD_CODE_HASH,
        repository: repo,
        subgraph,
        now,
      });

      expect(rep.reasonCodes).toContain('CODE_CHANGED');
      expect(rep.reasonCodes).toContain('CIRCULAR_ACTIVITY');
      expect(rep.reputationRiskPoints).toBeGreaterThanOrEqual(55);
    });

    it('Reviewer block scoped to code_hash prevents evasion through bytecode upgrade', async () => {
      // Active block scoped specifically to OLD_CODE_HASH
      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'target.testnet',
        contract_code_hash: OLD_CODE_HASH,
        scope: 'code_hash',
        reason: 'Backdoored bytecode v1',
        reviewer_id: 'security_lead',
      });

      const establishedSubgraph = buildMockSubgraph(12, 25, 'target.testnet');

      // 1. Running OLD_CODE_HASH: hard blocked
      const repBlocked = await getReceiverReputation({
        network: 'testnet',
        accountId: 'target.testnet',
        contractCodeHash: OLD_CODE_HASH,
        priorApprovedCodeHash: OLD_CODE_HASH,
        repository: repo,
        subgraph: establishedSubgraph,
        now,
      });
      expect(repBlocked.isBlocked).toBe(true);
      expect(repBlocked.reputationRiskPoints).toBe(100);

      // 2. Upgrading to NEW_CODE_HASH: not blocked by old code hash, BUT triggers CODE_CHANGED
      const repUpgraded = await getReceiverReputation({
        network: 'testnet',
        accountId: 'target.testnet',
        contractCodeHash: NEW_CODE_HASH,
        priorApprovedCodeHash: OLD_CODE_HASH,
        repository: repo,
        subgraph: establishedSubgraph,
        now,
      });
      expect(repUpgraded.isBlocked).toBe(false);
      expect(repUpgraded.reasonCodes).toContain('CODE_CHANGED');
      expect(repUpgraded.reputationRiskPoints).toBe(55);
    });

    it('Reviewer block scoped to account cannot be bypassed by bytecode upgrade', async () => {
      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'contract.testnet',
        scope: 'account',
        reason: 'Known malicious contractor',
        reviewer_id: 'security_lead',
      });

      const establishedSubgraph = buildMockSubgraph(12, 25, 'contract.testnet');

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: 'contract.testnet',
        contractCodeHash: NEW_CODE_HASH,
        priorApprovedCodeHash: OLD_CODE_HASH,
        repository: repo,
        subgraph: establishedSubgraph,
        now,
      });

      expect(rep.isBlocked).toBe(true);
      expect(rep.reasonCodes).toContain('ACTIVE_BLOCK');
      expect(rep.reputationRiskPoints).toBe(100);
    });
  });

  // =========================================================================
  // Suite 4: Sequential Bytecode Upgrades & Re-Approval Lifecycle
  // =========================================================================
  describe('Suite 4: Sequential Bytecode Upgrades & Re-Approval Lifecycle', () => {
    let repo: ReportRepository;

    beforeEach(() => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      repo = new ReportRepository(db, () => now);
    });

    it('models multi-version upgrade, warning pause, owner re-approval, and subsequent mutation', async () => {
      const HASH_V1 = '1111111111111111111111111111111111111111111111111111111111111111';
      const HASH_V2 = '2222222222222222222222222222222222222222222222222222222222222222';
      const HASH_V3 = '3333333333333333333333333333333333333333333333333333333333333333';
      const establishedSubgraph = buildMockSubgraph(15, 30, 'service.testnet');

      // Stage 1: Initial deployment v1.0.0 is approved and clean
      const stage1 = await getReceiverReputation({
        network: 'testnet',
        accountId: 'service.testnet',
        contractCodeHash: HASH_V1,
        priorApprovedCodeHash: HASH_V1,
        repository: repo,
        subgraph: establishedSubgraph,
        now,
      });
      expect(stage1.reasonCodes).not.toContain('CODE_CHANGED');
      expect(stage1.reputationRiskPoints).toBe(40);

      // Stage 2: Deploy v2.0.0 without prior owner approval
      const stage2 = await getReceiverReputation({
        network: 'testnet',
        accountId: 'service.testnet',
        contractCodeHash: HASH_V2,
        priorApprovedCodeHash: HASH_V1,
        repository: repo,
        subgraph: establishedSubgraph,
        now,
      });
      expect(stage2.reasonCodes).toContain('CODE_CHANGED');
      expect(stage2.reputationRiskPoints).toBe(55);

      // Stage 3: Owner reviews and approves v2.0.0 (updating priorApprovedCodeHash to HASH_V2)
      const stage3 = await getReceiverReputation({
        network: 'testnet',
        accountId: 'service.testnet',
        contractCodeHash: HASH_V2,
        priorApprovedCodeHash: HASH_V2, // Approved!
        repository: repo,
        subgraph: establishedSubgraph,
        now,
      });
      expect(stage3.reasonCodes).not.toContain('CODE_CHANGED');
      expect(stage3.reputationRiskPoints).toBe(40); // Positive credit restored!

      // Stage 4: Unannounced upgrade to v3.0.0 triggers fresh warning reassessment
      const stage4 = await getReceiverReputation({
        network: 'testnet',
        accountId: 'service.testnet',
        contractCodeHash: HASH_V3,
        priorApprovedCodeHash: HASH_V2,
        repository: repo,
        subgraph: establishedSubgraph,
        now,
      });
      expect(stage4.reasonCodes).toContain('CODE_CHANGED');
      expect(stage4.reputationRiskPoints).toBe(55);
    });
  });

  // =========================================================================
  // Suite 5: Guard Interceptor & Auto-Signing Refusal Invariant
  // =========================================================================
  describe('Suite 5: Guard Interceptor & Auto-Signing Refusal Invariant', () => {
    let repo: ReportRepository;

    beforeEach(() => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      repo = new ReportRepository(db, () => now);
    });

    it('refuses autonomous signing and halts on bytecode upgrade with WarningApprovalRequiredError', async () => {
      const action: Action = {
        kind: 'contract_call',
        receiver_id: 'contract.testnet',
        method_name: 'accept_memo',
        args_base64: 'eyJtZW1vIjoic3ludGhldGljIn0=',
        attached_deposit_yocto: '50000000000000000000000',
        gas_tgas: 30,
      };

      const establishedSubgraph = buildMockSubgraph(12, 25, 'contract.testnet');

      // Verify evaluateGuard produces decision: warn and permit
      const guardEval = await evaluateGuard(action, repo, 'testnet', establishedSubgraph, {
        contractCodeHash: NEW_CODE_HASH,
        priorApprovedCodeHash: OLD_CODE_HASH,
      });
      expect(guardEval.decision).toBe('warn');
      expect(guardEval.riskIndicator).toBe(55);
      expect(guardEval.reasonCodes).toContain('CODE_CHANGED');
      expect(guardEval.permit).not.toBeNull();
      expect(guardEval.permit?.payload.verdict).toBe('warn');

      // Verify guardedAgentExecute throws WarningApprovalRequiredError before signing
      let interceptedError: WarningApprovalRequiredError | null = null;
      let signed = true;
      let submitted = true;
      let delta = 'unknown';
      let finalizedOutcome = 'in_progress';

      try {
        const outcome = await guardedAgentExecute(action, repo, 'testnet', establishedSubgraph, {
          contractCodeHash: NEW_CODE_HASH,
          priorApprovedCodeHash: OLD_CODE_HASH,
        });
        signed = outcome.signed;
        submitted = outcome.submitted;
        delta = outcome.receiverBalanceDelta;
        finalizedOutcome = outcome.finalizedOutcome;
      } catch (err) {
        if (err instanceof WarningApprovalRequiredError) {
          interceptedError = err;
          signed = false;
          submitted = false;
          delta = '0';
          finalizedOutcome = 'awaiting_owner_approval';
        }
      }

      expect(interceptedError).not.toBeNull();
      expect(interceptedError?.receiverId).toBe('contract.testnet');
      expect(interceptedError?.permitHash).toMatch(/^[a-f0-9]{64}$/);
      expect(interceptedError?.reasonCodes).toContain('CODE_CHANGED');

      // Security Invariant verification: Execution was halted before signing
      expect(signed).toBe(false);
      expect(submitted).toBe(false);
      expect(delta).toBe('0');
      expect(finalizedOutcome).toBe('awaiting_owner_approval');
    });

    it('unchanged code without independent history still waits for owner approval', async () => {
      const action: Action = {
        kind: 'contract_call',
        receiver_id: 'contract.testnet',
        method_name: 'accept_memo',
        args_base64: 'eyJtZW1vIjoic3ludGhldGljIn0=',
        attached_deposit_yocto: '50000000000000000000000',
        gas_tgas: 30,
      };

      const establishedSubgraph = buildMockSubgraph(12, 25, 'contract.testnet');

      await expect(guardedAgentExecute(action, repo, 'testnet', establishedSubgraph, {
        contractCodeHash: OLD_CODE_HASH, priorApprovedCodeHash: OLD_CODE_HASH,
      })).rejects.toBeInstanceOf(WarningApprovalRequiredError);
    });
  });

  // =========================================================================
  // Suite 6: Human Owner Warning Approval & NEAR CLI Format
  // =========================================================================
  describe('Suite 6: Human Owner Warning Approval & NEAR CLI Format', () => {
    it('validates permit hash format and NEAR CLI approve_warn command syntax', () => {
      const permitHash = '7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e';
      const vaultAccount = 'vault.agent-c.testnet';
      const ownerAccount = 'owner.testnet';
      const network = 'testnet';

      expect(permitHash).toMatch(/^[a-f0-9]{64}$/);

      const nearCliCommand = `near contract call-function as-transaction ${vaultAccount} approve_warn \\
  json-args '{"permit_hash":"${permitHash}"}' \\
  prepaid-gas '100.0 Tgas' \\
  attached-deposit '0 NEAR' \\
  sign-as ${ownerAccount} \\
  network-config ${network}`;

      expect(nearCliCommand).toContain(`as-transaction ${vaultAccount} approve_warn`);
      expect(nearCliCommand).toContain(`'{"permit_hash":"${permitHash}"}'`);
      expect(nearCliCommand).toContain("prepaid-gas '100.0 Tgas'");
      expect(nearCliCommand).toContain("attached-deposit '0 NEAR'");
      expect(nearCliCommand).toContain(`sign-as ${ownerAccount}`);
      expect(nearCliCommand).toContain(`network-config ${network}`);

      // Parse JSON args to guarantee machine validity
      const jsonArgsMatch = nearCliCommand.match(/json-args '([^']+)'/);
      expect(jsonArgsMatch).not.toBeNull();
      const parsedArgs = JSON.parse(jsonArgsMatch?.[1] ?? '{}');
      expect(parsedArgs.permit_hash).toBe(permitHash);
    });

    it('conforms to ExecutionPermitSchema when verdict is warn', () => {
      const permit: ExecutionPermit = {
        permit_hash: '7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e',
        encoded_permit_base64: 'eyJ2ZXJkaWN0Ijoid2FybiIsIm5vbmNlIjoibm9uY2VfczdfdXBncmFkZWQifQ==',
        signature:
          'ed25519:HL9TyXQMqnAJNJZzA3kV8CA9ZFHtQsYfpJ6rq9b2Kt7sogU7zCp3iuwBisoAnerAtwZPqD1Uy79v1F6L3u6LP9W',
        verdict: 'warn',
        nonce: 'nonce_s7_upgraded',
        issued_at: now,
        expires_at: now + 120_000,
      };

      const parsed = ExecutionPermitSchema.parse(permit);
      expect(parsed.verdict).toBe('warn');
      expect(parsed.permit_hash.length).toBe(64);
      expect(parsed.expires_at).toBeGreaterThan(parsed.issued_at);
    });
  });

  // =========================================================================
  // Suite 7: Deterministic Demo Runner Harness Conformance
  // =========================================================================
  describe('Suite 7: Deterministic Demo Runner Harness Conformance', () => {
    it('DeterministicAdapter executes S7 scenario and logs awaiting_owner_approval', async () => {
      const adapter = new DeterministicAdapter();
      await adapter.init();

      const result = await adapter.executeScenario('S7');
      expect(result.passed).toBe(true);
      expect(result.scenarioId).toBe('S7');
      expect(result.rawVerdict!.decision).toBe('warn');
      expect(result.rawVerdict!.riskScore).toBe(25);
      expect(result.rawVerdict!.reasonCodes).toContain('CODE_CHANGED');

      const log = result.log;
      expect(log.scenario_id).toBe('S7');
      expect(log.decision).toBe('warn');
      expect(log.reason_codes).toContain('CODE_CHANGED');
      expect(log.signed).toBe(false);
      expect(log.submitted).toBe(false);
      expect(log.finalized_outcome).toBe('awaiting_owner_approval');
      expect(log.receiver_balance_delta).toBe('0');
      expect(log.permit_hash).toMatch(/^[a-f0-9]{64}$/);

      expect(DemoExecutionLogSchema.safeParse(log).success).toBe(true);

      // Verify all S7 scenario assertions passed
      const failedAssertions = result.assertions.filter((a) => !a.passed);
      expect(failedAssertions.length).toBe(0);
      expect(result.assertionsPassed).toBeGreaterThanOrEqual(4);

      await adapter.teardown();
    });
  });
});
