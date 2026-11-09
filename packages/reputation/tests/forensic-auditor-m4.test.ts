import { ReceiverReputationSchema } from '@counterparty-guard/shared';
import type { ReportRecord } from '@counterparty-guard/shared';
import { describe, expect, it } from 'vitest';
import { detectCircularFlow } from '../src/graph/circular.js';
import {
  DisjointSetUnion,
  type ReporterFundingLineage,
  clusterDependenceGroups,
} from '../src/graph/clustering.js';
import {
  FaucetRegistry,
} from '../src/graph/faucet.js';
import {
  InMemoryGraphProvider,
  traverseBoundedGraph,
} from '../src/graph/traversal.js';
import { getReceiverReputation } from '../src/scoring.js';
import { createDatabase } from '../src/storage/db.js';
import { runMigrations } from '../src/storage/migrations.js';
import { ReportRepository } from '../src/storage/repository.js';

describe('Forensic Auditor Independent Integrity & Stress Tests (M4)', () => {
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
      description: 'Stress test report',
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

  describe('1. Reviewer Authority & Active Block Invariants', () => {
    it('CRITICAL: 1,000 raw unreviewed reports NEVER trigger isBlocked = true', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      // Register and insert 1,000 unreviewed reports
      for (let i = 1; i <= 1000; i++) {
        repo.registerReporter({
          reporter_id: `flooder_${i}.testnet`,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });
        repo.insertReport(
          makeReport(`rep_${i}`, `flooder_${i}.testnet`, 'innocent-victim.testnet', 'submitted'),
        );
      }

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: 'innocent-victim.testnet',
        repository: repo,
        now,
      });

      expect(rep.isBlocked).toBe(false);
      expect(rep.rawReportCount).toBe(1000);
      expect(rep.unresolvedReportsCount).toBe(1000);
      expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    });

    it('CRITICAL: Expired active block does NOT trigger block', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      // Insert block that expired 1 hour ago
      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'reformed.testnet',
        scope: 'account',
        reason: 'Past violation',
        reviewer_id: 'admin.testnet',
        expires_at: now - 3600_000,
      });

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: 'reformed.testnet',
        repository: repo,
        now,
      });

      expect(rep.isBlocked).toBe(false);
      expect(rep.reputationRiskPoints).not.toBe(100);
      expect(rep.reasonCodes).not.toContain('ACTIVE_BLOCK');
    });

    it('CRITICAL: Code hash block triggers block when code hash matches', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const maliciousHash = 'bad_hash_99999999999999999999999999999999';
      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'some-accused.testnet',
        contract_code_hash: maliciousHash,
        scope: 'code_hash',
        reason: 'Known malicious contract bytecode',
        reviewer_id: 'auditor.testnet',
      });

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: 'some-accused.testnet',
        contractCodeHash: maliciousHash,
        repository: repo,
        now,
      });

      expect(rep.isBlocked).toBe(true);
      expect(rep.reputationRiskPoints).toBe(100);
      expect(rep.reasonCodes).toContain('ACTIVE_BLOCK');
      expect(rep.blockReason).toContain('Known malicious contract bytecode');
    });
  });

  describe('2. Bounded Graph Traversal Exact Limits', () => {
    it('stops at exactly 100 accounts and sets truncated = true when 101st account encountered', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'root.testnet';

      // Connect 105 leaves directly to root
      for (let i = 1; i <= 105; i++) {
        provider.addEdge({
          id: `tx_${i}`,
          source: seed,
          target: `leaf_${i}.testnet`,
          type: 'transfer',
          timestamp: now - 1000,
        });
      }

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: now,
        maxAccounts: 100,
      });

      expect(result.nodes.size).toBe(100);
      expect(result.coverage.accountsVisited).toBe(100);
      expect(result.coverage.truncated).toBe(true);
      expect(result.nodes.has(seed)).toBe(true);
    });

    it('stops at exactly 500 edges and sets truncated = true when 501st edge encountered', async () => {
      const provider = new InMemoryGraphProvider();
      const a = 'node_a.testnet';
      const b = 'node_b.testnet';

      for (let i = 1; i <= 550; i++) {
        provider.addEdge({
          id: `edge_${i}`,
          source: a,
          target: b,
          type: 'transfer',
          timestamp: now - i * 100,
        });
      }

      const result = await traverseBoundedGraph(provider, a, 'testnet', {
        asOfTimestamp: now,
        maxEdges: 500,
      });

      expect(result.edges.length).toBe(500);
      expect(result.coverage.edgesTraversed).toBe(500);
      expect(result.coverage.truncated).toBe(true);
    });

    it('never traverses hop 3 nodes even if limits are not reached', async () => {
      const provider = new InMemoryGraphProvider();
      provider.addEdges([
        {
          id: '1',
          source: 'h0.testnet',
          target: 'h1.testnet',
          type: 'transfer',
          timestamp: now - 1000,
        },
        {
          id: '2',
          source: 'h1.testnet',
          target: 'h2.testnet',
          type: 'transfer',
          timestamp: now - 1000,
        },
        {
          id: '3',
          source: 'h2.testnet',
          target: 'h3.testnet',
          type: 'transfer',
          timestamp: now - 1000,
        },
        {
          id: '4',
          source: 'h3.testnet',
          target: 'h4.testnet',
          type: 'transfer',
          timestamp: now - 1000,
        },
      ]);

      const result = await traverseBoundedGraph(provider, 'h0.testnet', 'testnet', {
        asOfTimestamp: now,
        maxHops: 2,
      });

      expect(result.nodes.has('h0.testnet')).toBe(true);
      expect(result.nodes.has('h1.testnet')).toBe(true);
      expect(result.nodes.has('h2.testnet')).toBe(true);
      expect(result.nodes.has('h3.testnet')).toBe(false);
      expect(result.nodes.has('h4.testnet')).toBe(false);
      expect(result.coverage.truncated).toBe(false);
    });
  });

  describe('3. DSU & Sybil Weight Capping Edge Cases', () => {
    it('100 Sybil reporters capped at exactly 1.0 aggregate weight (0.01 per report)', () => {
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();

      for (let i = 1; i <= 100; i++) {
        const id = `sybil_${i}.testnet`;
        reports.push(makeReport(`rep_${i}`, id));
        lineages.set(id, {
          reporterId: id,
          allInboundFunders: ['sybil-boss.testnet'],
          transferPeers: [],
        });
      }

      const res = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
      });

      expect(res.totalRawReports).toBe(100);
      expect(res.totalEffectiveWeight).toBeCloseTo(1.0, 5);
      expect(res.sybilDiscountApplied).toBe(true);
      expect(res.sybilDiscountAmount).toBeCloseTo(99.0, 5);
      expect(res.dependenceGroups.length).toBe(1);
      expect(res.dependenceGroups[0].effectiveWeight).toBe(1.0);
      expect(res.dependenceGroups[0].reporterCount).toBe(100);
      expect(res.reportWeightMap.get('rep_1')).toBeCloseTo(0.01, 5);
      expect(res.reportWeightMap.get('rep_100')).toBeCloseTo(0.01, 5);
    });

    it('Official faucets are never clustered into Sybil groups', () => {
      const registry = new FaucetRegistry();
      const testnetFaucets = [
        'faucet.testnet',
        'testnet',
        'v2.near-faucet.testnet',
        'friendbot.testnet',
      ];
      const sandboxFaucets = ['faucet.sandbox', 'sandbox', 'test.near'];
      const mainnetFaucets = ['near', 'faucet.near', 'faucet.fastnear.near'];

      for (const f of testnetFaucets) {
        expect(registry.isExempted('testnet', f)).toBe(true);
      }
      for (const f of sandboxFaucets) {
        expect(registry.isExempted('sandbox', f)).toBe(true);
      }
      for (const f of mainnetFaucets) {
        expect(registry.isExempted('mainnet', f)).toBe(true);
      }
    });

    it('DisjointSetUnion correctness under random connections', () => {
      const dsu = new DisjointSetUnion();
      for (let i = 1; i <= 10; i++) dsu.makeSet(`node_${i}`);

      dsu.union('node_1', 'node_2');
      dsu.union('node_2', 'node_3');
      expect(dsu.find('node_1')).toBe(dsu.find('node_3'));

      dsu.union('node_4', 'node_5');
      expect(dsu.find('node_1')).not.toBe(dsu.find('node_4'));

      dsu.union('node_3', 'node_5');
      expect(dsu.find('node_1')).toBe(dsu.find('node_5'));

      const comps = dsu.getComponents();
      const compWithNode1 = Array.from(comps.values()).find((c) => c.includes('node_1'));
      expect(compWithNode1?.sort()).toEqual(['node_1', 'node_2', 'node_3', 'node_4', 'node_5']);
    });
  });

  describe('4. Circular Flow BigInt Precision & Bounds', () => {
    it('handles astronomical yoctoNEAR volumes without precision loss or overflow', () => {
      // 10^32 yoctoNEAR (100,000,000 NEAR)
      const hugeYocto = '100000000000000000000000000000000';
      const provider = new InMemoryGraphProvider();
      provider.addEdges([
        {
          id: '1',
          source: 'whale_a.testnet',
          target: 'whale_b.testnet',
          amountYocto: hugeYocto,
          type: 'transfer',
          timestamp: now - 1000,
        },
        {
          id: '2',
          source: 'whale_b.testnet',
          target: 'whale_a.testnet',
          amountYocto: hugeYocto,
          type: 'transfer',
          timestamp: now - 1000,
        },
      ]);

      const nodes = new Map();
      nodes.set('whale_a.testnet', { accountId: 'whale_a.testnet', hop: 0, discoveredAt: now });
      nodes.set('whale_b.testnet', { accountId: 'whale_b.testnet', hop: 1, discoveredAt: now });

      const res = detectCircularFlow({
        graph: {
          seedAccountId: 'whale_a.testnet',
          nodes,
          edges: provider.getAdjacentEdges(['whale_a.testnet', 'whale_b.testnet'], {
            network: 'testnet',
            sinceTimestamp: 0,
          }),
          adjacency: new Map(),
          coverage: { accountsVisited: 2, edgesTraversed: 2, truncated: false, windowDays: 7 },
        },
        targetAccountId: 'whale_a.testnet',
        nowMs: now,
      });

      expect(res.circularActivityDetected).toBe(true);
      expect(res.circularVolumeYocto).toBe(hugeYocto);
      expect(res.circularActivityScore).toBe(50);
      expect(res.circularVolumeRatio).toBe(0.5);
    });

    it('ignores cycles of length >= 5 as out of bound', () => {
      const provider = new InMemoryGraphProvider();
      // 5-node cycle: 1 -> 2 -> 3 -> 4 -> 5 -> 1
      provider.addEdges([
        {
          id: '1',
          source: 'n1.testnet',
          target: 'n2.testnet',
          type: 'transfer',
          timestamp: now - 1000,
        },
        {
          id: '2',
          source: 'n2.testnet',
          target: 'n3.testnet',
          type: 'transfer',
          timestamp: now - 1000,
        },
        {
          id: '3',
          source: 'n3.testnet',
          target: 'n4.testnet',
          type: 'transfer',
          timestamp: now - 1000,
        },
        {
          id: '4',
          source: 'n4.testnet',
          target: 'n5.testnet',
          type: 'transfer',
          timestamp: now - 1000,
        },
        {
          id: '5',
          source: 'n5.testnet',
          target: 'n1.testnet',
          type: 'transfer',
          timestamp: now - 1000,
        },
      ]);

      const nodes = new Map();
      for (let i = 1; i <= 5; i++) {
        nodes.set(`n${i}.testnet`, { accountId: `n${i}.testnet`, hop: 1, discoveredAt: now });
      }

      const res = detectCircularFlow({
        graph: {
          seedAccountId: 'n1.testnet',
          nodes,
          edges: provider.getAdjacentEdges(Array.from(nodes.keys()), {
            network: 'testnet',
            sinceTimestamp: 0,
          }),
          adjacency: new Map(),
          coverage: { accountsVisited: 5, edgesTraversed: 5, truncated: false, windowDays: 7 },
        },
        targetAccountId: 'n1.testnet',
        nowMs: now,
        maxCycleLength: 4,
      });

      // Bounded detector ignores length 5
      expect(res.cycles.length).toBe(0);
      expect(res.circularActivityDetected).toBe(false);
    });
  });

  describe('5. ReceiverReputationSchema Conformance', () => {
    it('always passes schema parsing across all scenarios', async () => {
      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: 'random-user.testnet',
        now,
      });

      const parsed = ReceiverReputationSchema.parse(rep);
      expect(parsed).toBeDefined();
      expect(parsed.reputationRiskPoints).toBeGreaterThanOrEqual(0);
      expect(parsed.reputationRiskPoints).toBeLessThanOrEqual(100);
      expect(Number.isInteger(parsed.reputationRiskPoints)).toBe(true);
      expect(parsed.circularActivityScore).toBeGreaterThanOrEqual(0);
      expect(parsed.circularActivityScore).toBeLessThanOrEqual(100);
      expect(parsed.isBlocked).toBe(false);
    });
  });
});
