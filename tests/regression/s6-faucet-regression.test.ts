/**
 * @file tests/regression/s6-faucet-regression.test.ts
 * @description Automated regression test suite for Feature 49: Scenario S6 Shared Common Faucet Control.
 *
 * Core Security Invariants Verified:
 * 1. Faucet Exemption Registry Invariant:
 *    Accounts receiving initial funding or transactions from official testnet faucets
 *    (e.g., faucet.testnet, testnet, v2.near-faucet.testnet, friendbot.testnet, faucet.sandbox)
 *    MUST NEVER be clustered into malicious dependence groups.
 * 2. Independent Weight Preservation:
 *    Accounts funded by legitimate shared faucets preserve full independent reporting weights (1.0 each).
 *    Aggregate effective weight for N faucet-funded reporters is exactly N * 1.0 (no Sybil discounting).
 * 3. Machine Reason Codes & Risk Points:
 *    Generates reason code 'COMMON_FAUCET_EXEMPTED', does NOT generate 'DEPENDENT_REPORTS'.
 *    Reputation risk points set to 10 (clean unpenalized score), evaluating to decision: 'allow'.
 * 4. Faucet Laundering Evasion Resistance:
 *    Attacker accounts funded by both an exempted faucet AND a private attacker treasury are NOT
 *    granted immunity; the non-faucet funder causes Sybil clustering and weight capping to 1.0.
 */

import { randomUUID } from 'node:crypto';
import {
  type AccountAdjacency,
  type AccountNode,
  type BoundedSubgraph,
  DEFAULT_FAUCET_EXEMPTIONS,
  FaucetRegistry,
  type GraphEdge,
  InMemoryGraphProvider,
  ReportRepository,
  type ReporterFundingLineage,
  clusterDependenceGroups,
  createDatabase,
  getReceiverReputation,
  isFaucetExempted,
  runMigrations,
} from '@counterparty-guard/reputation';
import {
  type Action,
  ReceiverReportsResponseSchema,
  ReceiverReputationSchema,
  type ReportRecord,
} from '@counterparty-guard/shared';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it } from 'vitest';
import { buildServer } from '../../apps/api/src/server.js';
import { evaluateGuard } from '../../scripts/demo/harness/guard.js';

describe('Feature 49 Regression Suite: S6 Common Faucet Control & Exemption Registry', () => {
  const fixedNow = Date.now();
  let db: ReturnType<typeof createDatabase>;
  let repo: ReportRepository;
  let faucetRegistry: FaucetRegistry;

  function mockReport(
    reportId: string,
    reporterId: string,
    accused = 'user-b.testnet',
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
      category: 'other',
      description: 'Legitimate counterparty feedback from community user.',
      transaction_references: [`tx_${validReportId.slice(0, 8)}`],
      evidence_content_hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
      contract_code_hash: null,
      status: 'submitted',
      issued_at: fixedNow - 1000,
      expires_at: fixedNow + 86400000,
      nonce: `nonce_${validReportId.slice(0, 8)}`,
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
      const neighbor = `neighbor_${i}.testnet`;
      nodes.set(neighbor, { accountId: neighbor, hop: 1, discoveredAt: fixedNow });
      adjacency.set(neighbor, { inEdges: [], outEdges: [] });
    }

    const graphEdges: GraphEdge[] = edges.map((e, idx) => ({
      id: `edge_${idx}`,
      source: e.source.trim().toLowerCase(),
      target: e.target.trim().toLowerCase(),
      amountYocto: e.amountYocto ?? '10000000000000000000000000', // 10 NEAR
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
    db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    repo = new ReportRepository(db);
    faucetRegistry = new FaucetRegistry(repo, { loadDefaults: true });
  });

  // =========================================================================
  // 1. Multi-Account Faucet Distribution (5, 20, 50 faucet-funded accounts)
  // =========================================================================
  describe('1. Multi-Account Faucet Weight Preservation (5, 20, 50 accounts)', () => {
    it('S6 Baseline (5 faucet-funded accounts): preserves independent weights (total weight = 5.0)', () => {
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();
      const count = 5;

      for (let i = 1; i <= count; i++) {
        const reporterId = `legit_user_${i}.testnet`;
        const rep = mockReport(`rep_faucet_${i}`, reporterId);
        reports.push(rep);

        lineages.set(reporterId, {
          reporterId,
          directFunderId: 'faucet.testnet',
          grandFunderId: 'testnet',
          allInboundFunders: ['faucet.testnet', 'testnet'],
          transferPeers: [],
        });
      }

      const result = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
        faucetRegistry,
        now: fixedNow,
      });

      expect(result.totalRawReports).toBe(5);
      // Retain full independent weights: 5 * 1.0 = 5.0
      expect(result.totalEffectiveWeight).toBe(5.0);
      expect(result.sybilDiscountApplied).toBe(false);
      expect(result.sybilDiscountAmount).toBe(0.0);
      expect(result.dependenceGroups.length).toBe(0); // Zero malicious dependence groups formed
      expect(result.hasFaucetExemptions).toBe(true);
      expect(result.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');
      expect(result.reasonCodes).not.toContain('DEPENDENT_REPORTS');

      // Each individual report retains full 1.0 weight
      for (const r of reports) {
        expect(result.reportWeightMap.get(r.report_id)).toBe(1.0);
      }
    });

    it('S6 Mid-Scale (20 faucet-funded accounts): total weight = 20.0, risk = 10, is_blocked = false', async () => {
      const target = 'user-b.testnet';
      const count = 20;
      const reports: ReportRecord[] = [];
      const edges: Array<{ source: string; target: string; amountYocto: string }> = [];

      for (let i = 1; i <= count; i++) {
        const reporterId = `faucet_user_${i}.testnet`;
        repo.registerReporter({
          reporter_id: reporterId,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });

        const rep = mockReport(`rep_20_${i}`, reporterId, target);
        reports.push(rep);
        repo.insertReport(rep);

        edges.push({
          source: 'faucet.testnet',
          target: reporterId,
          amountYocto: '10000000000000000000000000',
        });
      }

      const subgraph = buildMockSubgraph(target, edges, 15);

      const clusteringResult = clusterDependenceGroups({
        network: 'testnet',
        reports,
        graph: subgraph,
        faucetRegistry,
        now: fixedNow,
      });

      expect(clusteringResult.totalRawReports).toBe(20);
      expect(clusteringResult.totalEffectiveWeight).toBe(20.0);
      expect(clusteringResult.sybilDiscountApplied).toBe(false);
      expect(clusteringResult.dependenceGroups.length).toBe(0);
      expect(clusteringResult.hasFaucetExemptions).toBe(true);

      const repResult = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        repository: repo,
        subgraph,
        faucetRegistry,
        now: fixedNow,
      });

      expect(ReceiverReputationSchema.safeParse(repResult).success).toBe(true);
      expect(repResult.isBlocked).toBe(false);
      expect(repResult.rawReportCount).toBe(20);
      expect(repResult.effectiveReportWeight).toBe(20.0);
      expect(repResult.reputationRiskPoints).toBe(10);
      expect(repResult.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');
      expect(repResult.reasonCodes).not.toContain('DEPENDENT_REPORTS');
    });

    it('S6 Stress Test (50 faucet-funded accounts): scales linearly to weight 50.0 without clustering', async () => {
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();
      const count = 50;

      for (let i = 1; i <= count; i++) {
        const reporterId = `faucet_scale_${i}.testnet`;
        reports.push(mockReport(`rep_50_${i}`, reporterId));
        lineages.set(reporterId, {
          reporterId,
          directFunderId: 'faucet.testnet',
          allInboundFunders: ['faucet.testnet'],
          transferPeers: [],
        });
      }

      const result = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
        faucetRegistry,
      });

      expect(result.totalRawReports).toBe(50);
      expect(result.totalEffectiveWeight).toBe(50.0);
      expect(result.sybilDiscountApplied).toBe(false);
      expect(result.dependenceGroups.length).toBe(0);
      expect(result.hasFaucetExemptions).toBe(true);
    });
  });

  // =========================================================================
  // 2. Multi-Hop Faucet Lineage & Network Registry Support
  // =========================================================================
  describe('2. Multi-Hop Lineage & Multi-Network Support', () => {
    it('exempts accounts across 2-hop funding lineage (Hop 1 faucet.testnet, Hop 2 testnet genesis)', () => {
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();

      for (let i = 1; i <= 6; i++) {
        const reporterId = `genesis_descendant_${i}.testnet`;
        reports.push(mockReport(`rep_gen_${i}`, reporterId));

        lineages.set(reporterId, {
          reporterId,
          directFunderId: 'faucet.testnet',
          grandFunderId: 'testnet',
          allInboundFunders: ['faucet.testnet', 'testnet'],
          transferPeers: [],
        });
      }

      const result = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
        faucetRegistry,
      });

      expect(result.totalRawReports).toBe(6);
      expect(result.totalEffectiveWeight).toBe(6.0);
      expect(result.dependenceGroups.length).toBe(0);
      expect(result.hasFaucetExemptions).toBe(true);
      expect(result.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');
    });

    it('verifies static registry defaults across testnet, sandbox, and mainnet with network isolation', () => {
      // Verify DEFAULT_FAUCET_EXEMPTIONS constant
      expect(DEFAULT_FAUCET_EXEMPTIONS.length).toBeGreaterThanOrEqual(10);

      // Testnet faucets
      expect(faucetRegistry.isExempted('testnet', 'faucet.testnet')).toBe(true);
      expect(faucetRegistry.isExempted('testnet', 'testnet')).toBe(true);
      expect(faucetRegistry.isExempted('testnet', 'v2.near-faucet.testnet')).toBe(true);
      expect(faucetRegistry.isExempted('testnet', 'friendbot.testnet')).toBe(true);

      // Sandbox faucets
      expect(faucetRegistry.isExempted('sandbox', 'faucet.sandbox')).toBe(true);
      expect(faucetRegistry.isExempted('sandbox', 'sandbox')).toBe(true);
      expect(faucetRegistry.isExempted('sandbox', 'test.near')).toBe(true);

      // Mainnet infrastructure
      expect(faucetRegistry.isExempted('mainnet', 'near')).toBe(true);
      expect(faucetRegistry.isExempted('mainnet', 'faucet.near')).toBe(true);
      expect(faucetRegistry.isExempted('mainnet', 'faucet.fastnear.near')).toBe(true);

      // Network isolation check: testnet faucet is NOT exempted on mainnet
      expect(faucetRegistry.isExempted('mainnet', 'faucet.testnet')).toBe(false);
      // Unknown account is NOT exempted
      expect(faucetRegistry.isExempted('testnet', 'random-stranger.testnet')).toBe(false);
    });
  });

  // =========================================================================
  // 3. Dynamic Custom Faucet Exemption & SQLite Synchronization
  // =========================================================================
  describe('3. Dynamic Faucet Registry & Database Synchronization', () => {
    it('supports runtime registration of new community faucets and respects active flag', () => {
      const customFaucet = 'community-faucet-2026.testnet';

      // Initially not exempted
      expect(faucetRegistry.isExempted('testnet', customFaucet)).toBe(false);

      // Add dynamic active exemption
      faucetRegistry.addExemption({
        exemptionId: 'custom-community-faucet-2026',
        network: 'testnet',
        faucetAccountId: customFaucet,
        label: 'Community Testnet Faucet 2026',
        exemptionType: 'faucet',
        isActive: true,
      });

      expect(faucetRegistry.isExempted('testnet', customFaucet)).toBe(true);

      // Verify accounts funded by this custom faucet are now exempted from clustering
      const reports: ReportRecord[] = [
        mockReport('rep_cust_1', 'user_a.testnet'),
        mockReport('rep_cust_2', 'user_b.testnet'),
      ];
      const lineages = new Map<string, ReporterFundingLineage>([
        [
          'user_a.testnet',
          {
            reporterId: 'user_a.testnet',
            allInboundFunders: [customFaucet],
            transferPeers: [],
          },
        ],
        [
          'user_b.testnet',
          {
            reporterId: 'user_b.testnet',
            allInboundFunders: [customFaucet],
            transferPeers: [],
          },
        ],
      ]);

      const result = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
        faucetRegistry,
      });

      expect(result.totalEffectiveWeight).toBe(2.0);
      expect(result.dependenceGroups.length).toBe(0);
      expect(result.hasFaucetExemptions).toBe(true);
      expect(result.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');
    });

    it('persists and synchronizes custom exemptions from SQLite repository', () => {
      db.prepare(`
        INSERT INTO faucet_exemptions (exemption_id, network, faucet_account_id, label, exemption_type, is_active, created_at, updated_at)
        VALUES ('db-faucet-01', 'testnet', 'db-seeded-faucet.testnet', 'DB Seeded Faucet', 'faucet', 1, ?, ?)
      `).run(fixedNow, fixedNow);

      const newRegistry = new FaucetRegistry(repo, { loadDefaults: true });
      expect(newRegistry.isExempted('testnet', 'db-seeded-faucet.testnet')).toBe(true);
      expect(isFaucetExempted('db-seeded-faucet.testnet', 'testnet', repo)).toBe(true);
    });
  });

  // =========================================================================
  // 4. Adversarial Evasion Resistance: Faucet Laundering Attempt
  // =========================================================================
  describe('4. Adversarial Evasion Resistance: Faucet Laundering', () => {
    it('defeats faucet laundering: Sybils funded by both faucet.testnet AND attacker treasury ARE clustered', () => {
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();
      const count = 10;
      const attackerFunder = 'evil-sybil-treasury.testnet';

      for (let i = 1; i <= count; i++) {
        const reporterId = `laundering_bot_${i}.testnet`;
        reports.push(mockReport(`rep_launder_${i}`, reporterId));

        // Bot received funds from BOTH legitimate faucet AND attacker treasury
        lineages.set(reporterId, {
          reporterId,
          directFunderId: attackerFunder,
          grandFunderId: 'faucet.testnet',
          allInboundFunders: ['faucet.testnet', attackerFunder],
          transferPeers: [],
        });
      }

      const result = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
        faucetRegistry,
      });

      // Crucial Security Assertion:
      // faucet.testnet is filtered out, leaving evil-sybil-treasury.testnet.
      // Because they all share evil-sybil-treasury.testnet, they ARE clustered and capped to 1.0!
      expect(result.totalRawReports).toBe(10);
      expect(result.totalEffectiveWeight).toBe(1.0);
      expect(result.sybilDiscountApplied).toBe(true);
      expect(result.dependenceGroups.length).toBe(1);
      expect(result.dependenceGroups[0].reporterCount).toBe(10);
      expect(result.dependenceGroups[0].commonFunderId).toBe(attackerFunder);

      // Both reason codes are emitted: faucet was seen, but Sybil discount was applied!
      expect(result.reasonCodes).toContain('DEPENDENT_REPORTS');
      expect(result.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');

      // Each report gets 1.0 / 10 = 0.1
      for (const r of reports) {
        expect(result.reportWeightMap.get(r.report_id)).toBeCloseTo(0.1);
      }
    });

    it('correctly handles hybrid mix: 5 legitimate faucet users + 10 Sybil bots', () => {
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();

      // 5 honest faucet users
      for (let i = 1; i <= 5; i++) {
        const id = `faucet_honest_${i}.testnet`;
        reports.push(mockReport(`rep_fh_${i}`, id));
        lineages.set(id, {
          reporterId: id,
          allInboundFunders: ['faucet.testnet'],
          transferPeers: [],
        });
      }

      // 10 Sybil bots sharing cartel funder
      for (let i = 1; i <= 10; i++) {
        const id = `cartel_bot_${i}.testnet`;
        reports.push(mockReport(`rep_cb_${i}`, id));
        lineages.set(id, {
          reporterId: id,
          allInboundFunders: ['cartel-boss.testnet'],
          transferPeers: [],
        });
      }

      const result = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
        faucetRegistry,
      });

      expect(result.totalRawReports).toBe(15);
      // 5 honest (5 * 1.0) + 1 Sybil cluster (1.0) = 6.0 total effective weight
      expect(result.totalEffectiveWeight).toBe(6.0);
      expect(result.dependenceGroups.length).toBe(1);
      expect(result.dependenceGroups[0].reporterCount).toBe(10);
      expect(result.sybilDiscountApplied).toBe(true);
      expect(result.hasFaucetExemptions).toBe(true);
      expect(result.reasonCodes).toContain('DEPENDENT_REPORTS');
      expect(result.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');
    });
  });

  // =========================================================================
  // 5. HTTP API Route Integration (GET /v1/receivers/:network/:account/reports)
  // =========================================================================
  describe('5. HTTP API Route Integration (Scenario S6 Faucet)', () => {
    let server: FastifyInstance;

    it('returns 200 with full individual weights and zero dependence groups over HTTP', async () => {
      const target = 'service-target.testnet';
      const graphProvider = new InMemoryGraphProvider();

      server = await buildServer({
        repository: repo,
        now: () => fixedNow,
        graphDataProvider: graphProvider,
      });

      // Seed 4 reports from accounts funded by faucet.testnet
      for (let i = 1; i <= 4; i++) {
        const reporterId = `faucet-rep-api-${i}.testnet`;
        repo.registerReporter({
          reporter_id: reporterId,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });

        repo.insertReport(mockReport(`rep_fapi_${i}`, reporterId, target));

        // Edge: faucet -> reporter
        graphProvider.addEdge({
          id: `faucet-edge-${i}`,
          source: 'faucet.testnet',
          target: reporterId,
          amountYocto: '10000000000000000000000000',
          timestamp: fixedNow - 3600000,
          type: 'transfer',
        });
        // Edge: reporter -> target
        graphProvider.addEdge({
          id: `call-edge-${i}`,
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

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);

      expect(ReceiverReportsResponseSchema.safeParse(body).success).toBe(true);
      expect(body.is_blocked).toBe(false);
      expect(body.total_reports).toBe(4);
      // Faucet users are NOT discounted: 4 * 1.0 = 4.0
      expect(body.effective_weight).toBeCloseTo(4.0, 2);
      expect(body.dependence_groups).toEqual([]);

      for (const r of body.reports) {
        expect(r.effective_weight).toBeCloseTo(1.0, 2);
      }

      await server.close();
    });
  });

  // =========================================================================
  // 6. Decision & Guard Interceptor Execution (evaluateGuard)
  // =========================================================================
  describe('6. Decision & Guard Interceptor Execution', () => {
    it('evaluates to decision: allow with risk = 10 for S6 faucet-funded counterparties', async () => {
      const target = 'user-b.testnet';

      // 2 reports from users funded by faucet.testnet
      for (let i = 1; i <= 2; i++) {
        const reporterId = `faucet_guard_user_${i}.testnet`;
        repo.registerReporter({
          reporter_id: reporterId,
          public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
          network: 'testnet',
        });
        repo.insertReport(mockReport(`rep_guard_f_${i}`, reporterId, target));
      }

      const edges: Array<{ source: string; target: string; amountYocto: string }> = [
        {
          source: 'faucet.testnet',
          target: 'faucet_guard_user_1.testnet',
          amountYocto: '10000000000000000000000000',
        },
        {
          source: 'faucet.testnet',
          target: 'faucet_guard_user_2.testnet',
          amountYocto: '10000000000000000000000000',
        },
        {
          source: 'faucet.testnet',
          target,
          amountYocto: '10000000000000000000000000',
        },
      ];

      const subgraph = buildMockSubgraph(target, edges, 8);

      const action: Action = {
        kind: 'transfer_near',
        receiver_id: target,
        amount_yocto: '50000000000000000000000',
      };

      const result = await evaluateGuard(action, repo, 'testnet', subgraph);

      expect(result.decision).toBe('allow');
      expect(result.riskIndicator).toBe(10);
      expect(result.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');
      expect(result.reasonCodes).not.toContain('DEPENDENT_REPORTS');
      expect(result.permit).not.toBeNull();
      expect(result.permit?.verdict).toBe('allow');
    });
  });
});
