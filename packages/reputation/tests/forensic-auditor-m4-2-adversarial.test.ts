import { type ReportRecord } from '@counterparty-guard/shared';
import { describe, expect, it } from 'vitest';
import { detectCircularFlow } from '../src/graph/circular.js';
import {
  type ReporterFundingLineage,
  clusterDependenceGroups,
} from '../src/graph/clustering.js';
import { FaucetRegistry } from '../src/graph/faucet.js';
import {
  type AccountAdjacency,
  type AccountNode,
  type BoundedSubgraph,
  type GraphEdge,
  InMemoryGraphProvider,
  traverseBoundedGraph,
} from '../src/graph/traversal.js';
import { getReceiverReputation } from '../src/scoring.js';
import { createDatabase } from '../src/storage/db.js';
import { runMigrations } from '../src/storage/migrations.js';
import { ReportRepository } from '../src/storage/repository.js';

describe('Auditor M4-2 Forensic Integrity & Remediation Verification Suite', () => {
  const now = 1700000000000;
  const oneDay = 86_400_000;

  function makeReport(
    id: string,
    reporterId: string,
    accused = 'target.testnet',
    status: ReportRecord['status'] = 'submitted',
  ): ReportRecord {
    return {
      report_id: id,
      network: 'testnet',
      accused_account_id: accused,
      reporter_id: reporterId,
      reporter_public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
      category: 'wash_trading',
      description: 'Forensic integrity audit report',
      transaction_references: [],
      evidence_content_hashes: [],
      contract_code_hash: null,
      status,
      issued_at: now - 1000,
      expires_at: now + oneDay,
      nonce: `nonce_${id}`,
      signature: 'ed25519:sig',
      dependence_group_id: null,
      created_at: now - 1000,
    };
  }

  function buildTestSubgraph(
    seedAccountId: string,
    edges: Array<{ source: string; target: string; amountYocto?: string; timestamp?: number }>,
  ): BoundedSubgraph {
    const nodes = new Map<string, AccountNode>();
    const adjacency = new Map<string, AccountAdjacency>();

    nodes.set(seedAccountId, { accountId: seedAccountId, hop: 0, discoveredAt: now });
    adjacency.set(seedAccountId, { inEdges: [], outEdges: [] });

    const graphEdges: GraphEdge[] = edges.map((e, idx) => ({
      id: `edge_${idx}`,
      source: e.source,
      target: e.target,
      amountYocto: e.amountYocto ?? '1000000000000000000000000',
      timestamp: e.timestamp ?? now - 1000,
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
        accountsVisited: nodes.size,
        edgesTraversed: graphEdges.length,
        truncated: false,
        windowDays: 7,
      },
    };
  }

  describe('1. Circular Flow: Guilt-by-Association & Canonical Edge Alignment Verification', () => {
    it('guarantees innocent account has 0 circularActivityScore when cycle exists only among neighbors', () => {
      const provider = new InMemoryGraphProvider();
      // Triangle wash-trading ring: ring1 -> ring2 -> ring3 -> ring1
      provider.addEdges([
        {
          id: 'e1',
          source: 'ring1.testnet',
          target: 'ring2.testnet',
          amountYocto: '1000000000000000000000000', // 1 NEAR
          type: 'transfer',
          timestamp: now - 1000,
        },
        {
          id: 'e2',
          source: 'ring2.testnet',
          target: 'ring3.testnet',
          amountYocto: '1000000000000000000000000',
          type: 'transfer',
          timestamp: now - 1000,
        },
        {
          id: 'e3',
          source: 'ring3.testnet',
          target: 'ring1.testnet',
          amountYocto: '1000000000000000000000000',
          type: 'transfer',
          timestamp: now - 1000,
        },
        // Innocent target has normal edge with ring1
        {
          id: 'e4',
          source: 'ring1.testnet',
          target: 'innocent-merchant.testnet',
          amountYocto: '500000000000000000000000', // 0.5 NEAR
          type: 'transfer',
          timestamp: now - 1000,
        },
      ]);

      const nodes = new Map();
      nodes.set('innocent-merchant.testnet', {
        accountId: 'innocent-merchant.testnet',
        hop: 0,
        discoveredAt: now,
      });
      nodes.set('ring1.testnet', { accountId: 'ring1.testnet', hop: 1, discoveredAt: now });
      nodes.set('ring2.testnet', { accountId: 'ring2.testnet', hop: 2, discoveredAt: now });
      nodes.set('ring3.testnet', { accountId: 'ring3.testnet', hop: 2, discoveredAt: now });

      const res = detectCircularFlow({
        graph: {
          seedAccountId: 'innocent-merchant.testnet',
          nodes,
          edges: provider.getAdjacentEdges(Array.from(nodes.keys()), {
            network: 'testnet',
            sinceTimestamp: 0,
          }),
          adjacency: new Map(),
          coverage: { accountsVisited: 4, edgesTraversed: 4, truncated: false, windowDays: 7 },
        },
        targetAccountId: 'innocent-merchant.testnet',
        nowMs: now,
      });

      expect(res.circularActivityDetected).toBe(false);
      expect(res.circularActivityScore).toBe(0);
      expect(res.circularVolumeRatio).toBe(0.0);
      expect(res.circularVolumeYocto).toBe('0');
      expect(res.cycles.length).toBe(0);
      expect(res.ringAccounts.length).toBe(0);
    });

    it('accurately aligns canonical rotated edges with path nodes', () => {
      const provider = new InMemoryGraphProvider();
      // Cycle: z_node -> m_node -> a_node -> z_node
      // Canonical order: a_node -> z_node -> m_node -> a_node
      provider.addEdges([
        {
          id: 'e_zm',
          source: 'z_node.testnet',
          target: 'm_node.testnet',
          amountYocto: '100',
          type: 'transfer',
          timestamp: now - 1000,
        },
        {
          id: 'e_ma',
          source: 'm_node.testnet',
          target: 'a_node.testnet',
          amountYocto: '200',
          type: 'transfer',
          timestamp: now - 1000,
        },
        {
          id: 'e_az',
          source: 'a_node.testnet',
          target: 'z_node.testnet',
          amountYocto: '300',
          type: 'transfer',
          timestamp: now - 1000,
        },
      ]);

      const nodes = new Map();
      nodes.set('a_node.testnet', { accountId: 'a_node.testnet', hop: 0, discoveredAt: now });
      nodes.set('m_node.testnet', { accountId: 'm_node.testnet', hop: 1, discoveredAt: now });
      nodes.set('z_node.testnet', { accountId: 'z_node.testnet', hop: 1, discoveredAt: now });

      const res = detectCircularFlow({
        graph: {
          seedAccountId: 'a_node.testnet',
          nodes,
          edges: provider.getAdjacentEdges(Array.from(nodes.keys()), {
            network: 'testnet',
            sinceTimestamp: 0,
          }),
          adjacency: new Map(),
          coverage: { accountsVisited: 3, edgesTraversed: 3, truncated: false, windowDays: 7 },
        },
        targetAccountId: 'a_node.testnet',
        nowMs: now,
      });

      expect(res.circularActivityDetected).toBe(true);
      expect(res.cycles.length).toBe(1);
      const cycle = res.cycles[0];

      expect(cycle.path[0]).toBe('a_node.testnet');
      expect(cycle.path[1]).toBe('z_node.testnet');
      expect(cycle.path[2]).toBe('m_node.testnet');
      expect(cycle.path[3]).toBe('a_node.testnet');

      expect(cycle.edges[0].source).toBe('a_node.testnet');
      expect(cycle.edges[0].target).toBe('z_node.testnet');
      expect(cycle.edges[1].source).toBe('z_node.testnet');
      expect(cycle.edges[1].target).toBe('m_node.testnet');
      expect(cycle.edges[2].source).toBe('m_node.testnet');
      expect(cycle.edges[2].target).toBe('a_node.testnet');
    });
  });

  describe('2. Sybil Exploit Prevention in Scoring Pipeline', () => {
    it('NEVER reduces riskPoints to 20 when circularActivityDetected is true during Sybil flood', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const accused = 'wash-trader.testnet';
      const circularYocto = '75000000000000000000000000'; // 75 NEAR

      const graphEdges = [
        { source: accused, target: 'partner.testnet', amountYocto: circularYocto },
        { source: 'partner.testnet', target: accused, amountYocto: circularYocto },
      ];

      // Attacker creates 10 Sybil reporters to flood reports against himself to trigger sybil discount
      for (let i = 1; i <= 10; i++) {
        const reporterId = `sybil_reporter_${i}.testnet`;
        repo.registerReporter({
          reporter_id: reporterId,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });
        repo.insertReport(makeReport(`rep_${i}`, reporterId, accused));

        // Connect Sybils to common funder
        graphEdges.push({
          source: 'sybil_funder.testnet',
          target: reporterId,
          amountYocto: '1000000000000000000000000',
        });
      }

      const subgraph = buildTestSubgraph(accused, graphEdges);

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: accused,
        repository: repo,
        subgraph,
        now,
      });

      expect(rep.circularActivityDetected).toBe(true);
      expect(rep.circularActivityScore).toBeGreaterThanOrEqual(50);
      expect(rep.reasonCodes).toContain('CIRCULAR_ACTIVITY');
      expect(rep.reasonCodes).toContain('DEPENDENT_REPORTS');

      // The exploit would have overwritten riskPoints to 20.
      // The authentic remediation must preserve risk >= circularActivityScore (>= 50).
      expect(rep.reputationRiskPoints).toBeGreaterThanOrEqual(50);
      expect(rep.reputationRiskPoints).not.toBe(20);
    });

    it('NEVER reduces riskPoints to 20 when code_changed is detected during Sybil flood', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const accused = 'mutated-contract.testnet';
      const graphEdges: Array<{ source: string; target: string; amountYocto?: string }> = [];

      for (let i = 1; i <= 5; i++) {
        const reporterId = `sybil_${i}.testnet`;
        repo.registerReporter({
          reporter_id: reporterId,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });
        repo.insertReport(makeReport(`rep_${i}`, reporterId, accused));
        graphEdges.push({
          source: 'sybil_boss.testnet',
          target: reporterId,
          amountYocto: '1000000000000000000000000',
        });
      }

      const subgraph = buildTestSubgraph(accused, graphEdges);

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: accused,
        repository: repo,
        subgraph,
        contractCodeHash: 'hash_v2_unapproved',
        priorApprovedCodeHash: 'hash_v1_approved',
        now,
      });

      expect(rep.reasonCodes).toContain('CODE_CHANGED');
      expect(rep.reasonCodes).toContain('DEPENDENT_REPORTS');
      // Must preserve riskPoints = 55 for unauthorized code mutation
      expect(rep.reputationRiskPoints).toBe(55);
    });
  });

  describe('3. Dense Graph Traversal Bounds & Capacity Verification', () => {
    it('traverses exactly 500 edges with truncated = true in a dense 600-edge mesh', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'center.testnet';

      // 30 nodes: 30 * 29 = 870 possible edges. Populate 600 edges.
      const nodes = [seed];
      for (let i = 1; i < 30; i++) {
        nodes.push(`node_${i}.testnet`);
      }

      let edgeCount = 0;
      for (let i = 0; i < 30 && edgeCount < 600; i++) {
        for (let j = 0; j < 30 && edgeCount < 600; j++) {
          if (i !== j) {
            edgeCount++;
            provider.addEdge({
              id: `edge_${edgeCount}`,
              source: nodes[i],
              target: nodes[j],
              type: 'transfer',
              timestamp: now - 500,
            });
          }
        }
      }

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: now,
        maxEdges: 500,
      });

      expect(result.edges.length).toBe(500);
      expect(result.coverage.edgesTraversed).toBe(500);
      expect(result.coverage.truncated).toBe(true);
    });
  });

  describe('4. Reviewer Authority Scope Isolation in Active Blocklist', () => {
    it('does NOT block an account when blocklist entry is scoped strictly to code_hash and account has different code hash', () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const targetAccount = 'contract-owner.testnet';
      const maliciousHash = '0x_bad_hash_12345';
      const cleanHash = '0x_clean_audited_hash_67890';

      // Insert active block with scope = 'code_hash'
      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: targetAccount,
        contract_code_hash: maliciousHash,
        scope: 'code_hash',
        reason: 'Malicious reentrancy exploit in bytecode',
        reviewer_id: 'security-reviewer.testnet',
      });

      // Query targetAccount running clean bytecode
      const blockClean = repo.getActiveBlock('testnet', targetAccount, cleanHash);
      expect(blockClean).toBeNull();

      // Query targetAccount with no code hash provided
      const blockNull = repo.getActiveBlock('testnet', targetAccount, null);
      expect(blockNull).toBeNull();

      // Query targetAccount with malicious bytecode
      const blockMalicious = repo.getActiveBlock('testnet', targetAccount, maliciousHash);
      expect(blockMalicious).not.toBeNull();
      expect(blockMalicious?.reason).toContain('Malicious reentrancy exploit');

      // Query a completely different account running the malicious bytecode
      const blockDiffAccount = repo.getActiveBlock(
        'testnet',
        'innocent-fork.testnet',
        maliciousHash,
      );
      expect(blockDiffAccount).toBeNull();
    });

    it('does NOT block an innocent account with same code hash when blocklist entry is scoped strictly to account', () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const badActor = 'bad-actor.testnet';
      const commonCodeHash = '0x_standard_multisig_hash';

      // Insert active block with scope = 'account'
      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: badActor,
        contract_code_hash: commonCodeHash,
        scope: 'account',
        reason: 'Compromised admin keys',
        reviewer_id: 'security-reviewer.testnet',
      });

      // Query innocent account running same multisig bytecode
      const blockInnocent = repo.getActiveBlock('testnet', 'good-actor.testnet', commonCodeHash);
      expect(blockInnocent).toBeNull();

      // Query bad actor
      const blockBad = repo.getActiveBlock('testnet', badActor, commonCodeHash);
      expect(blockBad).not.toBeNull();
    });
  });

  describe('5. Reviewer Authority Absolute Precedence: Massive Unreviewed Floods', () => {
    it('5,000 raw unreviewed reports across various categories NEVER set isBlocked = true', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const target = 'popular-defi.testnet';

      // 5,000 unreviewed reports
      for (let i = 1; i <= 5000; i++) {
        const repId = `reporter_${i}.testnet`;
        repo.registerReporter({
          reporter_id: repId,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });
        repo.insertReport(makeReport(`r_${i}`, repId, target, 'submitted'));
      }

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        repository: repo,
        now,
      });

      expect(rep.isBlocked).toBe(false);
      expect(rep.rawReportCount).toBe(5000);
      expect(rep.unresolvedReportsCount).toBe(5000);
      expect(rep.reasonCodes).not.toContain('ACTIVE_BLOCK');
    });
  });

  describe('6. Faucet Exemption Robustness', () => {
    it('preserves full report weight for reporters funded by legitimate shared faucets', () => {
      const faucetRegistry = new FaucetRegistry();
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();

      // 10 legitimate independent reporters all funded by official testnet faucet
      for (let i = 1; i <= 10; i++) {
        const id = `user_${i}.testnet`;
        reports.push(makeReport(`rep_${i}`, id));
        lineages.set(id, {
          reporterId: id,
          allInboundFunders: ['faucet.testnet'],
          transferPeers: [],
        });
      }

      const res = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
        faucetRegistry,
      });

      // Because faucet.testnet is exempted, they are NOT correlated into a Sybil cluster
      expect(res.sybilDiscountApplied).toBe(false);
      expect(res.dependenceGroups.length).toBe(0);
      expect(res.hasFaucetExemptions).toBe(true);
      expect(res.totalEffectiveWeight).toBe(10.0);
      expect(res.reportWeightMap.get('rep_1')).toBe(1.0);
      expect(res.reportWeightMap.get('rep_10')).toBe(1.0);
      expect(res.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');
      expect(res.reasonCodes).not.toContain('DEPENDENT_REPORTS');
    });
  });
});
