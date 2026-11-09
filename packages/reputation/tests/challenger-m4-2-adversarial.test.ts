import 'node:crypto';
import { ReceiverReputationSchema, type ReportRecord } from '@counterparty-guard/shared';
import { describe, expect, it } from 'vitest';
import { detectCircularFlow } from '../src/graph/circular.js';
import { type ReporterFundingLineage, clusterDependenceGroups } from '../src/graph/clustering.js';
import {
  FaucetRegistry,
} from '../src/graph/faucet.js';
import type {
  AccountAdjacency,
  AccountNode,
  BoundedSubgraph,
  GraphEdge,
} from '../src/graph/traversal.js';
import { getReceiverReputation } from '../src/scoring.js';
import { createDatabase } from '../src/storage/db.js';
import { runMigrations } from '../src/storage/migrations.js';
import { ReportRepository } from '../src/storage/repository.js';

describe('Adversarial Verification Suite: Milestone M4 Sybil, Faucet, Circular & Authority (challenger_m4_2)', () => {
  const now = 1700000000000;
  const oneDayMs = 24 * 60 * 60 * 1000;

  function mockReport(
    reportId: string,
    reporterId: string,
    accused = 'target-merchant.testnet',
    status: ReportRecord['status'] = 'submitted',
    timestamp = now,
  ): ReportRecord {
    return {
      report_id: reportId,
      network: 'testnet',
      accused_account_id: accused,
      reporter_id: reporterId,
      reporter_public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
      category: 'wash_trading',
      description: 'Adversarial challenge test allegation',
      transaction_references: [],
      evidence_content_hashes: [],
      contract_code_hash: null,
      status,
      issued_at: timestamp - 1000,
      expires_at: timestamp + 86400000,
      nonce: `nonce_${reportId}`,
      signature: 'ed25519:test_sig',
      dependence_group_id: null,
      created_at: timestamp - 1000,
    };
  }

  function buildMockSubgraph(
    accountsVisited: number,
    edgesTraversed: number,
    seedAccountId: string,
    edges: Array<{ source: string; target: string; amountYocto?: string; timestamp?: number }> = [],
  ): BoundedSubgraph {
    const nodes = new Map<string, AccountNode>();
    nodes.set(seedAccountId, { accountId: seedAccountId, hop: 0, discoveredAt: now });
    for (let i = 1; i < accountsVisited; i++) {
      nodes.set(`neighbor_${i}.testnet`, {
        accountId: `neighbor_${i}.testnet`,
        hop: 1,
        discoveredAt: now,
      });
    }

    const adjacency = new Map<string, AccountAdjacency>();
    for (const n of nodes.keys()) {
      adjacency.set(n, { inEdges: [], outEdges: [] });
    }

    const graphEdges: GraphEdge[] = edges.map((e, idx) => ({
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
  // 1. Scenario S4 Stress Test (Sybil Flood at 50, 100, 500 reports)
  // =========================================================================
  describe('1. Scenario S4 Stress Test (Sybil Flood Scale: 50, 100, 500 reports)', () => {
    it('S4 Stress Test: 50 reports from 50 Sybil accounts sharing common non-faucet funder cap to weight <= 1.0 and isBlocked = false', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);
      const faucetRegistry = new FaucetRegistry(repo);

      const count = 50;
      const reports: ReportRecord[] = [];
      const edges: Array<{ source: string; target: string; amountYocto: string }> = [];

      for (let i = 1; i <= count; i++) {
        const reporterId = `sybil_50_${i}.testnet`;
        repo.registerReporter({
          reporter_id: reporterId,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });
        const rep = mockReport(`rep_50_${i}`, reporterId, 'target-merchant.testnet');
        reports.push(rep);
        repo.insertReport(rep);

        edges.push({
          source: 'common-attacker-treasury.testnet',
          target: reporterId,
          amountYocto: '5000000000000000000000000',
        });
      }

      const subgraph = buildMockSubgraph(60, 120, 'target-merchant.testnet', edges);

      const clusteringResult = clusterDependenceGroups({
        network: 'testnet',
        reports,
        graph: subgraph,
        faucetRegistry,
      });

      // Assert aggregate effective weight is strictly <= 1.0
      expect(clusteringResult.totalRawReports).toBe(50);
      expect(clusteringResult.totalEffectiveWeight).toBeLessThanOrEqual(1.0);
      expect(clusteringResult.totalEffectiveWeight).toBe(1.0);
      expect(clusteringResult.sybilDiscountApplied).toBe(true);
      expect(clusteringResult.sybilDiscountAmount).toBe(49.0);
      expect(clusteringResult.dependenceGroups.length).toBe(1);
      expect(clusteringResult.dependenceGroups[0].reporterCount).toBe(50);
      expect(clusteringResult.dependenceGroups[0].effectiveWeight).toBe(1.0);
      expect(clusteringResult.dependenceGroups[0].commonFunderId).toBe(
        'common-attacker-treasury.testnet',
      );

      // Pro-rata per-report weight: 1.0 / 50 = 0.02
      for (let i = 1; i <= count; i++) {
        expect(clusteringResult.reportWeightMap.get(`rep_50_${i}`)).toBeCloseTo(0.02);
      }

      // Assert through scoring pipeline: isBlocked MUST be false
      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: 'target-merchant.testnet',
        repository: repo,
        subgraph,
        faucetRegistry,
        now,
      });

      expect(rep.isBlocked).toBe(false);
      expect(rep.effectiveReportWeight).toBeLessThanOrEqual(1.0);
      expect(rep.reputationRiskPoints).toBe(40);
      expect(rep.reasonCodes).toContain('DEPENDENT_REPORTS');
      expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    });

    it('S4 Stress Test: 100 reports from 100 Sybil accounts sharing 2-hop grand funder cap to weight <= 1.0 and isBlocked = false', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);
      const faucetRegistry = new FaucetRegistry(repo);

      const count = 100;
      const reports: ReportRecord[] = [];
      const edges: Array<{ source: string; target: string; amountYocto: string }> = [];

      // Grand funder funds 5 intermediate funding hubs, which fund the 100 reporters
      for (let h = 1; h <= 5; h++) {
        edges.push({
          source: 'master-sybil-grandfunder.testnet',
          target: `hub_${h}.testnet`,
          amountYocto: '100000000000000000000000000',
        });
      }

      for (let i = 1; i <= count; i++) {
        const hubId = `hub_${(i % 5) + 1}.testnet`;
        const reporterId = `sybil_100_${i}.testnet`;
        repo.registerReporter({
          reporter_id: reporterId,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });
        const rep = mockReport(`rep_100_${i}`, reporterId, 'target-merchant.testnet');
        reports.push(rep);
        repo.insertReport(rep);

        edges.push({
          source: hubId,
          target: reporterId,
          amountYocto: '1000000000000000000000000',
        });
      }

      const subgraph = buildMockSubgraph(120, 250, 'target-merchant.testnet', edges);

      const clusteringResult = clusterDependenceGroups({
        network: 'testnet',
        reports,
        graph: subgraph,
        faucetRegistry,
      });

      // Connected via 2-hop grand funder
      expect(clusteringResult.totalRawReports).toBe(100);
      expect(clusteringResult.totalEffectiveWeight).toBeLessThanOrEqual(1.0);
      expect(clusteringResult.totalEffectiveWeight).toBe(1.0);
      expect(clusteringResult.sybilDiscountApplied).toBe(true);

      for (let i = 1; i <= count; i++) {
        expect(clusteringResult.reportWeightMap.get(`rep_100_${i}`)).toBeCloseTo(0.01);
      }

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: 'target-merchant.testnet',
        repository: repo,
        subgraph,
        faucetRegistry,
        now,
      });

      expect(rep.isBlocked).toBe(false);
      expect(rep.effectiveReportWeight).toBeLessThanOrEqual(1.0);
      expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    });

    it('S4 Stress Test: 500 reports flood across 500 Sybil accounts cap to weight <= 1.0 and isBlocked = false', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);
      const faucetRegistry = new FaucetRegistry(repo);

      const count = 500;
      const reports: ReportRecord[] = [];
      const edges: Array<{ source: string; target: string; amountYocto: string }> = [];

      for (let i = 1; i <= count; i++) {
        const reporterId = `sybil_500_${i}.testnet`;
        const rep = mockReport(`rep_500_${i}`, reporterId, 'target-merchant.testnet');
        reports.push(rep);

        edges.push({
          source: 'massive-attacker.testnet',
          target: reporterId,
          amountYocto: '1000000000000000000000000',
        });
      }

      const subgraph = buildMockSubgraph(520, 520, 'target-merchant.testnet', edges);

      const clusteringResult = clusterDependenceGroups({
        network: 'testnet',
        reports,
        graph: subgraph,
        faucetRegistry,
      });

      expect(clusteringResult.totalRawReports).toBe(500);
      expect(clusteringResult.totalEffectiveWeight).toBeLessThanOrEqual(1.0);
      expect(clusteringResult.totalEffectiveWeight).toBe(1.0);
      expect(clusteringResult.sybilDiscountApplied).toBe(true);
      expect(clusteringResult.sybilDiscountAmount).toBe(499.0);

      // Pro-rata distribution: 1.0 / 500 = 0.002
      expect(clusteringResult.reportWeightMap.get('rep_500_1')).toBeCloseTo(0.002);
      expect(clusteringResult.reportWeightMap.get('rep_500_500')).toBeCloseTo(0.002);

      // Populate DB in batch transaction using node:sqlite exec
      db.exec('BEGIN TRANSACTION;');
      const repStmt = db.prepare(`
        INSERT INTO reporters (reporter_id, public_key, network, total_reports, created_at, updated_at)
        VALUES (?, 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3', 'testnet', 0, ?, ?)
      `);
      for (let i = 1; i <= count; i++) {
        repStmt.run(`sybil_500_${i}.testnet`, now, now);
      }

      const stmt = db.prepare(`
        INSERT INTO reports (
          report_id, network, accused_account_id, reporter_id, reporter_public_key,
          category, description, transaction_references, evidence_content_hashes,
          contract_code_hash, status, issued_at, expires_at, nonce, signature,
          dependence_group_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, '[]', '[]', NULL, ?, ?, ?, ?, ?, NULL, ?, ?)
      `);
      for (const r of reports) {
        stmt.run(
          r.report_id,
          r.network,
          r.accused_account_id,
          r.reporter_id,
          r.reporter_public_key,
          r.category,
          r.description,
          r.status,
          r.issued_at,
          r.expires_at,
          r.nonce,
          r.signature,
          r.created_at,
          r.created_at,
        );
      }
      db.exec('COMMIT;');

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: 'target-merchant.testnet',
        repository: repo,
        subgraph,
        faucetRegistry,
        now,
      });

      expect(rep.isBlocked).toBe(false);
      expect(rep.rawReportCount).toBe(500);
      expect(rep.effectiveReportWeight).toBeLessThanOrEqual(1.0);
      expect(rep.reputationRiskPoints).toBe(40);
      expect(rep.reasonCodes).toContain('DEPENDENT_REPORTS');
      expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    });

    it('S4 Stress Test: Mixed scenario with 50 Sybils + 5 independent reporters', async () => {
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();

      // 50 Sybils
      for (let i = 1; i <= 50; i++) {
        const id = `sybil_mixed_${i}.testnet`;
        reports.push(mockReport(`rep_sm_${i}`, id));
        lineages.set(id, {
          reporterId: id,
          allInboundFunders: ['common-sybil-boss.testnet'],
          transferPeers: [],
        });
      }

      // 5 independent honest reporters
      for (let i = 1; i <= 5; i++) {
        const id = `honest_${i}.testnet`;
        reports.push(mockReport(`rep_honest_${i}`, id));
        lineages.set(id, {
          reporterId: id,
          allInboundFunders: [`honest-funder-${i}.testnet`],
          transferPeers: [],
        });
      }

      const res = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
      });

      expect(res.totalRawReports).toBe(55);
      // Sybil cluster (1.0) + 5 singletons (5 * 1.0) = 6.0
      expect(res.totalEffectiveWeight).toBe(6.0);
      expect(res.dependenceGroups.length).toBe(1);
      expect(res.dependenceGroups[0].reporterCount).toBe(50);
      expect(res.dependenceGroups[0].effectiveWeight).toBe(1.0);
    });
  });

  // =========================================================================
  // 2. Scenario S6 Stress Test (Shared Faucet Control)
  // =========================================================================
  describe('2. Scenario S6 Stress Test (Shared Faucet Control)', () => {
    it('S6 Stress Test: 10 independent accounts whose common funder is faucet.testnet retain individual weight 1.0 (total weight = 10.0)', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);
      const faucetRegistry = new FaucetRegistry(repo);

      const count = 10;
      const reports: ReportRecord[] = [];
      const edges: Array<{ source: string; target: string; amountYocto: string }> = [];

      for (let i = 1; i <= count; i++) {
        const repId = `faucet_user_${i}.testnet`;
        repo.registerReporter({
          reporter_id: repId,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });
        const rep = mockReport(`rep_faucet_${i}`, repId, 'faucet-funded-target.testnet');
        reports.push(rep);
        repo.insertReport(rep);

        // All 10 accounts funded by official testnet faucet
        edges.push({
          source: 'faucet.testnet',
          target: repId,
          amountYocto: '10000000000000000000000000', // 10 NEAR
        });
      }

      const subgraph = buildMockSubgraph(25, 30, 'faucet-funded-target.testnet', edges);

      const clusteringResult = clusterDependenceGroups({
        network: 'testnet',
        reports,
        graph: subgraph,
        faucetRegistry,
      });

      // Assert they are NOT clustered into a single Sybil group
      expect(clusteringResult.dependenceGroups.length).toBe(0);
      expect(clusteringResult.sybilDiscountApplied).toBe(false);
      expect(clusteringResult.sybilDiscountAmount).toBe(0);

      // Assert each retains independent weight 1.0 (total weight = 10.0)
      expect(clusteringResult.totalRawReports).toBe(10);
      expect(clusteringResult.totalEffectiveWeight).toBe(10.0);

      for (let i = 1; i <= count; i++) {
        expect(clusteringResult.reportWeightMap.get(`rep_faucet_${i}`)).toBe(1.0);
      }

      // Assert reasonCodes includes 'COMMON_FAUCET_EXEMPTED' and not 'DEPENDENT_REPORTS'
      expect(clusteringResult.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');
      expect(clusteringResult.reasonCodes).not.toContain('DEPENDENT_REPORTS');

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: 'faucet-funded-target.testnet',
        repository: repo,
        subgraph,
        faucetRegistry,
        now,
      });

      expect(rep.isBlocked).toBe(false);
      expect(rep.rawReportCount).toBe(10);
      expect(rep.effectiveReportWeight).toBe(10.0);
      expect(rep.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');
      expect(rep.reasonCodes).not.toContain('DEPENDENT_REPORTS');
      expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    });

    it('S6 Stress Test: 10 independent accounts whose common funder is testnet (genesis registrar)', async () => {
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();

      for (let i = 1; i <= 10; i++) {
        const id = `genesis_user_${i}.testnet`;
        reports.push(mockReport(`rep_genesis_${i}`, id));
        lineages.set(id, {
          reporterId: id,
          allInboundFunders: ['testnet'],
          transferPeers: [],
        });
      }

      const res = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
      });

      expect(res.dependenceGroups.length).toBe(0);
      expect(res.totalEffectiveWeight).toBe(10.0);
      expect(res.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');
      expect(res.reasonCodes).not.toContain('DEPENDENT_REPORTS');
    });

    it('S6 Stress Test: Mixed faucet ecosystem across testnet, v2 faucet, friendbot, and sandbox', () => {
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();
      const faucets = ['faucet.testnet', 'testnet', 'v2.near-faucet.testnet', 'friendbot.testnet'];

      for (let i = 1; i <= 12; i++) {
        const id = `diverse_faucet_user_${i}.testnet`;
        const faucet = faucets[i % faucets.length];
        reports.push(mockReport(`rep_df_${i}`, id));
        lineages.set(id, {
          reporterId: id,
          allInboundFunders: [faucet],
          transferPeers: [],
        });
      }

      const res = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
      });

      expect(res.dependenceGroups.length).toBe(0);
      expect(res.totalEffectiveWeight).toBe(12.0);
      expect(res.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');
    });

    it('S6 Stress Test: Case-insensitive and trimmed faucet identifier matching', () => {
      const registry = new FaucetRegistry();

      expect(registry.isExempted('testnet', '  FAUCET.TESTNET  ')).toBe(true);
      expect(registry.isExempted('testnet', 'TESTNET')).toBe(true);
      expect(registry.isExempted('testnet', 'V2.NEAR-FAUCET.TESTNET')).toBe(true);
      expect(registry.isExempted('sandbox', 'FAUCET.SANDBOX')).toBe(true);
      expect(registry.isExempted('mainnet', 'NEAR')).toBe(true);
      expect(registry.isExempted('mainnet', 'FAUCET.NEAR')).toBe(true);
    });
  });

  // =========================================================================
  // 3. Scenario S5 Stress Test (Circular Activity Ring)
  // =========================================================================
  describe('3. Scenario S5 Stress Test (Circular Activity Ring)', () => {
    it('S5 Stress Test: 2-node reciprocal loop (ping-pong) detects circular flow and score in [0, 100]', async () => {
      const yoctoForward = '50000000000000000000000000'; // 50 NEAR
      const yoctoBack = '40000000000000000000000000'; // 40 NEAR
      const otherInbound = '10000000000000000000000000'; // 10 NEAR

      const subgraph = buildMockSubgraph(5, 10, 'alice.testnet', [
        { source: 'alice.testnet', target: 'bob.testnet', amountYocto: yoctoForward },
        { source: 'bob.testnet', target: 'alice.testnet', amountYocto: yoctoBack },
        { source: 'charlie.testnet', target: 'alice.testnet', amountYocto: otherInbound },
      ]);

      const result = detectCircularFlow({
        graph: subgraph,
        targetAccountId: 'alice.testnet',
        nowMs: now,
      });

      expect(result.circularActivityDetected).toBe(true);
      expect(result.cycles.length).toBe(1);
      expect(result.cycles[0].cycleLength).toBe(2);
      // Bottleneck volume is min(50 NEAR, 40 NEAR) = 40 NEAR
      expect(result.cycles[0].volumeYocto).toBe(yoctoBack);

      // Score must be integer strictly within [0, 100]
      expect(result.circularActivityScore).toBeGreaterThanOrEqual(0);
      expect(result.circularActivityScore).toBeLessThanOrEqual(100);
      expect(Number.isInteger(result.circularActivityScore)).toBe(true);

      // Total incident volume = 50 (out) + 40 (in) + 10 (in) = 100 NEAR
      // Incident circular volume = 40 NEAR -> ratio = 40/100 = 0.40 -> score = 40
      expect(result.circularActivityScore).toBe(40);
      expect(result.ringAccounts).toContain('alice.testnet');
      expect(result.ringAccounts).toContain('bob.testnet');

      // Verify scoring pipeline integration
      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: 'alice.testnet',
        subgraph,
        now,
      });

      expect(rep.circularActivityDetected).toBe(true);
      expect(rep.circularActivityScore).toBe(40);
      expect(rep.reasonCodes).toContain('CIRCULAR_ACTIVITY');
      expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    });

    it('S5 Stress Test: 3-node wash trading ring (A -> B -> C -> A) computes circularActivityScore in [0, 100]', async () => {
      const circularYocto = '75000000000000000000000000'; // 75 NEAR
      const outsideYocto = '25000000000000000000000000'; // 25 NEAR

      const subgraph = buildMockSubgraph(8, 15, 'node-a.testnet', [
        { source: 'node-a.testnet', target: 'node-b.testnet', amountYocto: circularYocto },
        { source: 'node-b.testnet', target: 'node-c.testnet', amountYocto: circularYocto },
        { source: 'node-c.testnet', target: 'node-a.testnet', amountYocto: circularYocto },
        { source: 'external.testnet', target: 'node-a.testnet', amountYocto: outsideYocto },
      ]);

      const result = detectCircularFlow({
        graph: subgraph,
        targetAccountId: 'node-a.testnet',
        nowMs: now,
      });

      expect(result.circularActivityDetected).toBe(true);
      expect(result.cycles.length).toBe(1);
      expect(result.cycles[0].cycleLength).toBe(3);
      expect(result.cycles[0].volumeYocto).toBe(circularYocto);
      expect(result.circularActivityScore).toBeGreaterThanOrEqual(0);
      expect(result.circularActivityScore).toBeLessThanOrEqual(100);

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: 'node-a.testnet',
        subgraph,
        now,
      });

      expect(rep.circularActivityDetected).toBe(true);
      expect(rep.reasonCodes).toContain('CIRCULAR_ACTIVITY');
      expect(rep.reputationRiskPoints).toBeGreaterThanOrEqual(result.circularActivityScore);
      expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    });

    it('S5 Stress Test: Arbitrary BigInt yoctoNEAR precision without integer overflow (10^36 yoctoNEAR)', () => {
      const hugeYocto = '1000000000000000000000000000000000000'; // 10^36 yoctoNEAR
      const smallerHuge = '800000000000000000000000000000000000'; // 8 * 10^35 yoctoNEAR

      const subgraph = buildMockSubgraph(4, 6, 'whale-1.testnet', [
        { source: 'whale-1.testnet', target: 'whale-2.testnet', amountYocto: hugeYocto },
        { source: 'whale-2.testnet', target: 'whale-1.testnet', amountYocto: smallerHuge },
      ]);

      const result = detectCircularFlow({
        graph: subgraph,
        targetAccountId: 'whale-1.testnet',
        nowMs: now,
      });

      expect(result.circularActivityDetected).toBe(true);
      expect(result.cycles[0].volumeYocto).toBe(smallerHuge);
      expect(result.circularActivityScore).toBeGreaterThanOrEqual(0);
      expect(result.circularActivityScore).toBeLessThanOrEqual(100);
    });

    it('S5 Stress Test: Temporal window boundary (edges older than 7 days ignored)', () => {
      const eightDaysAgo = now - 8 * oneDayMs;

      const subgraph = buildMockSubgraph(6, 6, 'old-ring-a.testnet', [
        { source: 'old-ring-a.testnet', target: 'old-ring-b.testnet', timestamp: eightDaysAgo },
        { source: 'old-ring-b.testnet', target: 'old-ring-c.testnet', timestamp: eightDaysAgo },
        { source: 'old-ring-c.testnet', target: 'old-ring-a.testnet', timestamp: eightDaysAgo },
      ]);

      const result = detectCircularFlow({
        graph: subgraph,
        targetAccountId: 'old-ring-a.testnet',
        nowMs: now,
        windowDays: 7,
      });

      expect(result.circularActivityDetected).toBe(false);
      expect(result.circularActivityScore).toBe(0);
      expect(result.cycles.length).toBe(0);
    });

    it('S5 Stress Test: Self-loops (A -> A) are ignored and do not create false circular alerts', () => {
      const subgraph = buildMockSubgraph(3, 4, 'self-loop-user.testnet', [
        { source: 'self-loop-user.testnet', target: 'self-loop-user.testnet', amountYocto: '1000' },
        { source: 'self-loop-user.testnet', target: 'peer.testnet', amountYocto: '2000' },
      ]);

      const result = detectCircularFlow({
        graph: subgraph,
        targetAccountId: 'self-loop-user.testnet',
        nowMs: now,
      });

      expect(result.circularActivityDetected).toBe(false);
      expect(result.cycles.length).toBe(0);
    });
  });

  // =========================================================================
  // 4. Reviewer Authority Invariant Stress Tests
  // =========================================================================
  describe('4. Reviewer Authority Invariant Stress Tests', () => {
    it('Reviewer Authority Invariant: 10,000 unreviewed reports produce isBlocked: false', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const accusedId = 'innocent-victim-merchant.testnet';
      const count = 10_000;

      // Register reporter
      repo.registerReporter({
        reporter_id: 'mass-bot.testnet',
        public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
        network: 'testnet',
      });

      // Insert 10,000 unreviewed reports within a single transaction for maximum speed
      db.exec('BEGIN TRANSACTION;');
      const stmt = db.prepare(`
        INSERT INTO reports (
          report_id, network, accused_account_id, reporter_id, reporter_public_key,
          category, description, transaction_references, evidence_content_hashes,
          contract_code_hash, status, issued_at, expires_at, nonce, signature,
          dependence_group_id, created_at, updated_at
        ) VALUES (?, 'testnet', ?, 'mass-bot.testnet', 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          'drainer', 'Mass unreviewed allegation', '[]', '[]', NULL, 'submitted', ?, ?, ?, 'ed25519:sig', NULL, ?, ?)
      `);

      for (let i = 1; i <= count; i++) {
        stmt.run(
          `mass_rep_${i}`,
          accusedId,
          now - 1000,
          now + 86400000,
          `nonce_${i}`,
          now - 1000,
          now - 1000,
        );
      }
      db.exec('COMMIT;');

      // Verify 10,000 reports are present in DB
      const inDbCount = repo.getReportsByAccused('testnet', accusedId).length;
      expect(inDbCount).toBe(10_000);

      const subgraph = buildMockSubgraph(15, 20, accusedId);

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: accusedId,
        repository: repo,
        subgraph,
        now,
      });

      // Absolute Reviewer Authority Invariant:
      // Even 10,000 unreviewed reports CANNOT trigger a hard block!
      expect(rep.isBlocked).toBe(false);
      expect(rep.rawReportCount).toBe(10_000);
      expect(rep.unresolvedReportsCount).toBe(10_000);
      expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    });

    it('Reviewer Authority Invariant: Active block in SQLite produces isBlocked: true, ACTIVE_BLOCK, and 100 risk points', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const accusedId = 'confirmed-drainer.testnet';

      // 1. Initially without active block -> isBlocked: false
      const repBefore = await getReceiverReputation({
        network: 'testnet',
        accountId: accusedId,
        repository: repo,
        now,
      });
      expect(repBefore.isBlocked).toBe(false);

      // 2. Reviewer executes active block
      const blockOutcome = repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: accusedId,
        scope: 'account',
        reason: 'Confirmed wallet drainer phishing contract from sec-ops forensics',
        reviewer_id: 'alice_lead_reviewer',
      });

      expect(blockOutcome.blocklist_revision).toBe(1);

      // 3. Now getReceiverReputation must return isBlocked: true with absolute precedence
      const repAfter = await getReceiverReputation({
        network: 'testnet',
        accountId: accusedId,
        repository: repo,
        now,
      });

      expect(repAfter.isBlocked).toBe(true);
      expect(repAfter.reputationRiskPoints).toBe(100);
      expect(repAfter.reasonCodes).toContain('ACTIVE_BLOCK');
      expect(repAfter.reasonCodes).toContain('REVIEWED_BLOCKLIST_MATCH');
      expect(repAfter.blockReason).toBe(
        'Confirmed wallet drainer phishing contract from sec-ops forensics',
      );
      expect(ReceiverReputationSchema.safeParse(repAfter).success).toBe(true);
    });

    it('Reviewer Authority Invariant: Revoked block immediately restores isBlocked: false', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const accusedId = 'rehabilitated-merchant.testnet';

      // Create block
      const block = repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: accusedId,
        scope: 'account',
        reason: 'Temporary precautionary block',
        reviewer_id: 'alice',
      });

      // Confirm blocked
      const repBlocked = await getReceiverReputation({
        network: 'testnet',
        accountId: accusedId,
        repository: repo,
        now,
      });
      expect(repBlocked.isBlocked).toBe(true);

      // Revoke block
      repo.revokeActiveBlock(block.entry_id, {
        reviewer_id: 'alice',
        reason: 'Investigation concluded with clear legitimate provenance',
        revoked_at: now + 60000,
      });

      // Must be restored to isBlocked: false
      const repRevoked = await getReceiverReputation({
        network: 'testnet',
        accountId: accusedId,
        repository: repo,
        now: now + 60000,
      });

      expect(repRevoked.isBlocked).toBe(false);
      expect(repRevoked.reasonCodes).not.toContain('ACTIVE_BLOCK');
      expect(repRevoked.blockReason).toBeUndefined();
    });

    it('Reviewer Authority Invariant: Expired block evaluates as isBlocked: false', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const accusedId = 'time-bounded-block.testnet';

      // Block with expires_at in the past
      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: accusedId,
        scope: 'account',
        reason: 'Expired quarantine',
        reviewer_id: 'alice',
        expires_at: now - 5000, // expired 5 seconds ago
      });

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: accusedId,
        repository: repo,
        now,
      });

      expect(rep.isBlocked).toBe(false);
      expect(rep.reasonCodes).not.toContain('ACTIVE_BLOCK');
    });

    it('Reviewer Authority Invariant: Code-hash specific block targets matching bytecode hash across hosts', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repo = new ReportRepository(db, () => now);

      const maliciousHash = '33333333333333333333333333333333';
      const cleanHash = '44444444444444444444444444444444';

      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'contract-account.testnet',
        contract_code_hash: maliciousHash,
        scope: 'code_hash',
        reason: 'Bytecode drainer exploit detected',
        reviewer_id: 'sec-ops',
      });

      // Evaluation with malicious code hash on host B -> isBlocked: true
      const repMalicious = await getReceiverReputation({
        network: 'testnet',
        accountId: 'contract-account.testnet',
        contractCodeHash: maliciousHash,
        repository: repo,
        now,
      });
      expect(repMalicious.isBlocked).toBe(true);

      // Evaluation with clean code hash on host C -> isBlocked: false
      const repClean = await getReceiverReputation({
        network: 'testnet',
        accountId: 'host-c.testnet',
        contractCodeHash: cleanHash,
        repository: repo,
        now,
      });
      expect(repClean.isBlocked).toBe(false);
    });
  });
});
