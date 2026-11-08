/**
 * @file tests/regression/s4-flood-regression.test.ts
 * @description Automated regression test suite for Feature 48: Scenario S4 False-Report Flood Attack.
 *
 * Core Security Invariants Verified:
 * 1. Absolute Reviewer Authority Invariant:
 *    Multi-account flood of raw unreviewed allegations (20, 50, 100 reports) NEVER triggers is_blocked: true.
 *    Active hard blocks strictly require authenticated human reviewer authority.
 * 2. Group Weight Capping Invariant (Sybil Discounting):
 *    Accounts sharing common non-faucet funding progenitors (1-hop direct funder or 2-hop grandfunder)
 *    or direct transfer rings are clustered into a single dependence group whose aggregate effective
 *    weight is capped to <= 1.0 (specifically 1.0 independent source equivalent).
 * 3. Pro-Rata Report Weight Distribution:
 *    Each report in a clustered dependence group receives pro-rata effective weight (1.0 / count).
 * 4. Machine Reason Codes & Risk Points:
 *    Clustering generates reason code 'DEPENDENT_REPORTS', sybilDiscountApplied: true, and sets
 *    reputationRiskPoints = 20, evaluating to decision: 'allow' in the guard evaluation pipeline.
 */

import {
  type AccountAdjacency,
  type AccountNode,
  type BoundedSubgraph,
  FaucetRegistry,
  type GraphEdge,
  InMemoryGraphProvider,
  ReportRepository,
  type ReporterFundingLineage,
  clusterDependenceGroups,
  createDatabase,
  getReceiverReputation,
  runMigrations,
} from '@counterparty-guard/reputation';
import {
  type Action,
  ReceiverReportsResponseSchema,
  ReceiverReputationSchema,
  type ReportRecord,
  type ReportSignablePayload,
  generateKeyPair,
  signReportPayload,
} from '@counterparty-guard/shared';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it } from 'vitest';
import { buildServer } from '../../apps/api/src/server.js';
import { evaluateGuard } from '../../scripts/demo/harness/guard.js';

import { randomUUID } from 'node:crypto';

describe('Feature 48 Regression Suite: S4 False-Report Flood Attack & Sybil Discounting', () => {
  const fixedNow = Date.now(); // Dynamic current epoch so reports are never expired
  let repo: ReportRepository;

  function mockReport(
    reportId: string,
    reporterId: string,
    accused = 'popular-service.testnet',
    overrides: Partial<ReportRecord> = {},
  ): ReportRecord {
    const validReportId =
      reportId.includes('-') && reportId.length === 36 ? reportId : randomUUID();
    return {
      report_id: validReportId,
      network: 'testnet',
      accused_account_id: accused,
      reporter_id: reporterId,
      reporter_public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
      category: 'phishing',
      description: 'Coordinated false allegation from Sybil bot cluster.',
      transaction_references: [`tx_${reportId}`],
      evidence_content_hashes: ['a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e'],
      contract_code_hash: null,
      status: 'submitted',
      issued_at: fixedNow - 1000,
      expires_at: fixedNow + 86400000,
      nonce: `nonce_${reportId}`,
      signature: 'ed25519:test_sig',
      dependence_group_id: null,
      created_at: fixedNow - 1000,
      ...overrides,
    };
  }

  function buildMockSubgraph(
    seedAccountId: string,
    edges: Array<{ source: string; target: string; amountYocto?: string; timestamp?: number }>,
    extraAccounts = 10,
  ): BoundedSubgraph {
    const nodes = new Map<string, AccountNode>();
    nodes.set(seedAccountId, { accountId: seedAccountId, hop: 0, discoveredAt: fixedNow });

    const adjacency = new Map<string, AccountAdjacency>();
    adjacency.set(seedAccountId, { inEdges: [], outEdges: [] });

    for (let i = 1; i <= extraAccounts; i++) {
      const neighbor = `seed_neighbor_${i}.testnet`;
      nodes.set(neighbor, { accountId: neighbor, hop: 1, discoveredAt: fixedNow });
      adjacency.set(neighbor, { inEdges: [], outEdges: [] });
    }

    const graphEdges: GraphEdge[] = edges.map((e, idx) => ({
      id: `edge_${idx}`,
      source: e.source.trim().toLowerCase(),
      target: e.target.trim().toLowerCase(),
      amountYocto: e.amountYocto ?? '1000000000000000000000000',
      timestamp: e.timestamp ?? fixedNow - 3600000,
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

  beforeEach(() => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    repo = new ReportRepository(db);
  });

  // =========================================================================
  // 1. Multi-Account Sybil Flood Scaling Invariants (20, 50, 100 allegations)
  // =========================================================================
  describe('1. Multi-Scale Sybil Flood Invariants (20, 50, 100 allegations)', () => {
    it('S4 Baseline (20 Sybil accounts): aggregate weight capped to <= 1.0, is_blocked = false, risk = 20', async () => {
      const target = 'popular-service.testnet';
      const commonFunder = 'sybil-parent.testnet';
      const count = 20;
      const reports: ReportRecord[] = [];
      const edges: Array<{ source: string; target: string; amountYocto: string }> = [];

      for (let i = 1; i <= count; i++) {
        const reporterId = `sybil-${i}.testnet`;
        repo.registerReporter({
          reporter_id: reporterId,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });

        const rep = mockReport(`rep_s4_${i}`, reporterId, target);
        reports.push(rep);
        repo.insertReport(rep);

        // Funding connection: common non-faucet funder -> Sybil reporter
        edges.push({
          source: commonFunder,
          target: reporterId,
          amountYocto: '500000000000000000000000',
        });
      }

      const subgraph = buildMockSubgraph(target, edges, 12);

      // 1. Direct Engine Clustering Assertion
      const clusteringResult = clusterDependenceGroups({
        network: 'testnet',
        reports,
        graph: subgraph,
        repository: repo,
        now: fixedNow,
      });

      expect(clusteringResult.totalRawReports).toBe(20);
      expect(clusteringResult.totalEffectiveWeight).toBe(1.0);
      expect(clusteringResult.totalEffectiveWeight).toBeLessThanOrEqual(1.0);
      expect(clusteringResult.sybilDiscountApplied).toBe(true);
      expect(clusteringResult.sybilDiscountAmount).toBe(19.0);
      expect(clusteringResult.dependenceGroups.length).toBe(1);
      expect(clusteringResult.dependenceGroups[0].reporterCount).toBe(20);
      expect(clusteringResult.dependenceGroups[0].effectiveWeight).toBe(1.0);
      expect(clusteringResult.dependenceGroups[0].commonFunderId).toBe(commonFunder);
      expect(clusteringResult.dependenceGroups[0].faucetExempted).toBe(false);
      expect(clusteringResult.reasonCodes).toContain('DEPENDENT_REPORTS');

      // Pro-rata distribution: 1.0 / 20 = 0.05 per report
      for (let i = 1; i <= count; i++) {
        expect(clusteringResult.reportWeightMap.get(reports[i - 1].report_id)).toBeCloseTo(0.05);
      }

      // 2. Comprehensive Reputation Scoring Pipeline Assertion
      const repResult = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        repository: repo,
        subgraph,
        now: fixedNow,
      });

      expect(ReceiverReputationSchema.safeParse(repResult).success).toBe(true);
      expect(repResult.isBlocked).toBe(false);
      expect(repResult.rawReportCount).toBe(20);
      expect(repResult.effectiveReportWeight).toBe(1.0);
      expect(repResult.reputationRiskPoints).toBe(20);
      expect(repResult.reasonCodes).toContain('DEPENDENT_REPORTS');
      expect(repResult.reasonCodes).not.toContain('ACTIVE_BLOCK');
      expect(repResult.dependenceGroups.length).toBe(1);
      expect(repResult.dependenceGroups[0].reporterCount).toBe(20);
    });

    it('S4 Mid-Scale (50 Sybil accounts): aggregate weight capped to <= 1.0, pro-rata 0.02, is_blocked = false', async () => {
      const target = 'popular-service.testnet';
      const commonFunder = 'attacker-master-treasury.testnet';
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

        const rep = mockReport(`rep_50_${i}`, reporterId, target);
        reports.push(rep);
        repo.insertReport(rep);

        edges.push({
          source: commonFunder,
          target: reporterId,
          amountYocto: '1000000000000000000000000',
        });
      }

      const subgraph = buildMockSubgraph(target, edges, 10);

      const clusteringResult = clusterDependenceGroups({
        network: 'testnet',
        reports,
        graph: subgraph,
        repository: repo,
        now: fixedNow,
      });

      expect(clusteringResult.totalRawReports).toBe(50);
      expect(clusteringResult.totalEffectiveWeight).toBe(1.0);
      expect(clusteringResult.totalEffectiveWeight).toBeLessThanOrEqual(1.0);
      expect(clusteringResult.sybilDiscountApplied).toBe(true);
      expect(clusteringResult.sybilDiscountAmount).toBe(49.0);
      expect(clusteringResult.dependenceGroups.length).toBe(1);
      expect(clusteringResult.dependenceGroups[0].reporterCount).toBe(50);

      // Pro-rata distribution: 1.0 / 50 = 0.02 per report
      for (let i = 1; i <= count; i++) {
        expect(clusteringResult.reportWeightMap.get(reports[i - 1].report_id)).toBeCloseTo(0.02);
      }

      const repResult = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        repository: repo,
        subgraph,
        now: fixedNow,
      });

      expect(repResult.isBlocked).toBe(false);
      expect(repResult.rawReportCount).toBe(50);
      expect(repResult.effectiveReportWeight).toBe(1.0);
      expect(repResult.reputationRiskPoints).toBe(20);
      expect(repResult.reasonCodes).toContain('DEPENDENT_REPORTS');
    });

    it('S4 Large-Scale (100 Sybil accounts via 2-hop grandfunder hierarchy): capped to <= 1.0, is_blocked = false', async () => {
      const target = 'popular-service.testnet';
      const grandFunder = 'grand-sybil-progenitor.testnet';
      const count = 100;
      const reports: ReportRecord[] = [];
      const edges: Array<{ source: string; target: string; amountYocto: string }> = [];

      // Grandfunder funds 5 intermediate funding hubs (Hop 2 -> Hop 1)
      for (let h = 1; h <= 5; h++) {
        edges.push({
          source: grandFunder,
          target: `sybil_hub_${h}.testnet`,
          amountYocto: '50000000000000000000000000',
        });
      }

      // 5 intermediate hubs fund 20 Sybil reporters each (100 total)
      for (let i = 1; i <= count; i++) {
        const hubId = `sybil_hub_${(i % 5) + 1}.testnet`;
        const reporterId = `sybil_100_${i}.testnet`;

        repo.registerReporter({
          reporter_id: reporterId,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });

        const rep = mockReport(`rep_100_${i}`, reporterId, target);
        reports.push(rep);
        repo.insertReport(rep);

        edges.push({
          source: hubId,
          target: reporterId,
          amountYocto: '1000000000000000000000000',
        });
      }

      const subgraph = buildMockSubgraph(target, edges, 10);

      const clusteringResult = clusterDependenceGroups({
        network: 'testnet',
        reports,
        graph: subgraph,
        repository: repo,
        now: fixedNow,
      });

      expect(clusteringResult.totalRawReports).toBe(100);
      expect(clusteringResult.totalEffectiveWeight).toBe(1.0);
      expect(clusteringResult.totalEffectiveWeight).toBeLessThanOrEqual(1.0);
      expect(clusteringResult.sybilDiscountApplied).toBe(true);
      expect(clusteringResult.sybilDiscountAmount).toBe(99.0);

      // Pro-rata distribution: 1.0 / 100 = 0.01 per report
      for (let i = 1; i <= count; i++) {
        expect(clusteringResult.reportWeightMap.get(reports[i - 1].report_id)).toBeCloseTo(0.01);
      }

      const repResult = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        repository: repo,
        subgraph,
        now: fixedNow,
      });

      expect(repResult.isBlocked).toBe(false);
      expect(repResult.rawReportCount).toBe(100);
      expect(repResult.effectiveReportWeight).toBe(1.0);
      expect(repResult.reputationRiskPoints).toBe(20);
      expect(repResult.reasonCodes).toContain('DEPENDENT_REPORTS');
    });
  });

  // =========================================================================
  // 2. Peer-to-Peer Transfer Rings & Mesh Clustered Topologies
  // =========================================================================
  describe('2. Topology Variations: Peer Transfers & Mixed Flood', () => {
    it('clusters peer-to-peer transaction rings without explicit external funder into 1 group (weight <= 1.0)', () => {
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();

      // Ring of 8 Sybil bots: bot_1 -> bot_2 -> bot_3 -> ... -> bot_8 -> bot_1
      for (let i = 1; i <= 8; i++) {
        const id = `ring_bot_${i}.testnet`;
        const nextId = `ring_bot_${(i % 8) + 1}.testnet`;
        reports.push(mockReport(`rep_ring_${i}`, id));
        lineages.set(id, {
          reporterId: id,
          allInboundFunders: [],
          transferPeers: [nextId],
        });
      }

      const result = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
      });

      expect(result.totalRawReports).toBe(8);
      expect(result.totalEffectiveWeight).toBe(1.0);
      expect(result.sybilDiscountApplied).toBe(true);
      expect(result.dependenceGroups.length).toBe(1);
      expect(result.dependenceGroups[0].reporterCount).toBe(8);
      expect(result.dependenceGroups[0].effectiveWeight).toBe(1.0);

      // Each report gets 1.0 / 8 = 0.125
      for (let i = 1; i <= 8; i++) {
        expect(result.reportWeightMap.get(reports[i - 1].report_id)).toBeCloseTo(0.125);
      }
    });

    it('correctly partitions mixed flood: 30 coordinated Sybils + 4 independent reporters = 5.0 total weight', () => {
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();

      // 30 Sybils sharing common funder
      for (let i = 1; i <= 30; i++) {
        const id = `sybil_bot_${i}.testnet`;
        reports.push(mockReport(`rep_sybil_${i}`, id));
        lineages.set(id, {
          reporterId: id,
          allInboundFunders: ['sybil-cartel-treasury.testnet'],
          transferPeers: [],
        });
      }

      // 4 independent honest reporters with disjoint funders
      for (let i = 1; i <= 4; i++) {
        const id = `independent_honest_${i}.testnet`;
        reports.push(mockReport(`rep_honest_${i}`, id));
        lineages.set(id, {
          reporterId: id,
          allInboundFunders: [`honest-private-funder-${i}.testnet`],
          transferPeers: [],
        });
      }

      const result = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
      });

      expect(result.totalRawReports).toBe(34);
      // Sybil cluster (1.0) + 4 independent singletons (4 * 1.0) = 5.0 total effective weight
      expect(result.totalEffectiveWeight).toBe(5.0);
      expect(result.sybilDiscountApplied).toBe(true);
      expect(result.dependenceGroups.length).toBe(1);
      expect(result.dependenceGroups[0].reporterCount).toBe(30);

      // Sybil reports discounted to 1.0 / 30 ~ 0.0333
      expect(result.reportWeightMap.get(reports[0].report_id)).toBeCloseTo(1 / 30);

      // Independent reports retain full weight 1.0
      for (let i = 30; i < 34; i++) {
        expect(result.reportWeightMap.get(reports[i].report_id)).toBe(1.0);
      }
    });
  });

  // =========================================================================
  // 3. Absolute Reviewer Authority Invariant Across Layers
  // =========================================================================
  describe('3. Absolute Reviewer Authority Invariant', () => {
    it('50 unreviewed raw reports CANNOT trigger hard block; only reviewer active_block can set is_blocked = true', async () => {
      const target = 'service-target.testnet';
      const keyPair = generateKeyPair();

      // Submit 50 unreviewed reports
      for (let i = 1; i <= 50; i++) {
        const repId = `reporter_${i}.testnet`;
        repo.registerReporter({
          reporter_id: repId,
          public_key: keyPair.publicKey,
          network: 'testnet',
        });
        repo.insertReport(mockReport(`flood_${i}`, repId, target));
      }

      // Without human review: is_blocked is strictly false
      const beforeRep = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        repository: repo,
        now: fixedNow,
      });

      expect(beforeRep.isBlocked).toBe(false);
      expect(beforeRep.rawReportCount).toBe(50);

      // Now human reviewer executes an active_block
      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: target,
        scope: 'account',
        reason: 'Confirmed malicious phishing operation by human reviewer.',
        reviewer_id: 'human_moderator_01',
      });

      // After human review: isBlocked becomes true with 100 risk points
      const afterRep = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        repository: repo,
        now: fixedNow,
      });

      expect(afterRep.isBlocked).toBe(true);
      expect(afterRep.reputationRiskPoints).toBe(100);
      expect(afterRep.reasonCodes).toContain('ACTIVE_BLOCK');
      expect(afterRep.reasonCodes).toContain('REVIEWED_BLOCKLIST_MATCH');
    });
  });

  // =========================================================================
  // 4. HTTP API Route Integration (GET /v1/receivers/:network/:account/reports)
  // =========================================================================
  describe('4. HTTP API Route Integration (Scenario S4 Flood)', () => {
    let server: FastifyInstance;

    it('returns 200 with discounted effective_weight: 1.0 and is_blocked: false over HTTP', async () => {
      const target = 'popular-service.testnet';
      const commonFunder = 'sybil-parent.testnet';
      const graphProvider = new InMemoryGraphProvider();

      server = await buildServer({
        repository: repo,
        now: () => fixedNow,
        graphDataProvider: graphProvider,
      });

      // Seed 20 reports and funding edges
      for (let i = 1; i <= 20; i++) {
        const reporterId = `sybil-api-${i}.testnet`;
        repo.registerReporter({
          reporter_id: reporterId,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });

        repo.insertReport(mockReport(`rep_api_${i}`, reporterId, target));

        // Edge 1: funder -> reporter
        graphProvider.addEdge({
          id: `fund-${i}`,
          source: commonFunder,
          target: reporterId,
          amountYocto: '500000000000000000000000',
          timestamp: fixedNow - 3600000,
          type: 'transfer',
        });
        // Edge 2: reporter -> target
        graphProvider.addEdge({
          id: `call-${i}`,
          source: reporterId,
          target,
          amountYocto: '0',
          timestamp: fixedNow - 1800000,
          type: 'contract_call',
        });
      }

      const res = await server.inject({
        method: 'GET',
        url: `/v1/receivers/testnet/${target}/reports`,
      });

      if (res.statusCode !== 200) {
        console.error('API Error body:', res.body);
      }
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);

      // Conforms to ReceiverReportsResponseSchema
      expect(ReceiverReportsResponseSchema.safeParse(body).success).toBe(true);
      expect(body.is_blocked).toBe(false);
      expect(body.total_reports).toBe(20);
      expect(body.effective_weight).toBeCloseTo(1.0, 2);
      expect(body.dependence_groups.length).toBeGreaterThanOrEqual(1);
      expect(body.dependence_groups[0].reporterCount).toBe(20);
      expect(body.dependence_groups[0].effectiveWeight).toBeCloseTo(1.0, 2);

      // Each individual report is discounted to 0.05
      for (const r of body.reports) {
        expect(r.effective_weight).toBeCloseTo(0.05, 2);
      }
    });
  });

  // =========================================================================
  // 5. Decision & Guard Interceptor Execution (evaluateGuard)
  // =========================================================================
  describe('5. Decision & Guard Interceptor Execution', () => {
    it('evaluates to decision: allow and produces permit for S4 flood attack', async () => {
      const target = 'popular-service.testnet';
      const commonFunder = 'sybil-parent.testnet';
      const edges: Array<{ source: string; target: string; amountYocto: string }> = [];

      // Seed 20 Sybil reports in repository
      for (let i = 1; i <= 20; i++) {
        const reporterId = `sybil-guard-${i}.testnet`;
        repo.registerReporter({
          reporter_id: reporterId,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });
        repo.insertReport(mockReport(`rep_guard_${i}`, reporterId, target));

        edges.push({
          source: commonFunder,
          target: reporterId,
          amountYocto: '500000000000000000000000',
        });
      }

      const subgraph = buildMockSubgraph(target, edges, 15);

      const action: Action = {
        kind: 'transfer_near',
        receiver_id: target,
        amount_yocto: '50000000000000000000000',
      };

      const result = await evaluateGuard(action, repo, 'testnet', subgraph);

      expect(result.decision).toBe('allow');
      expect(result.riskIndicator).toBe(20);
      expect(result.reasonCodes).toContain('DEPENDENT_REPORTS');
      expect(result.permit).not.toBeNull();
      expect(result.permit?.verdict).toBe('allow');
    });
  });
});
