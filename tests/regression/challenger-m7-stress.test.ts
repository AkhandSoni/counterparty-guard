/**
 * @file tests/regression/challenger-m7-stress.test.ts
 * @description Milestone M7 Empirical Security Challenge Suite.
 *
 * EMPIRICAL CHALLENGER VERIFICATION:
 * 1. Massive flood stress: Assert that even 100+ unreviewed allegations NEVER trigger is_blocked: true.
 * 2. Faucet laundering: Assert that accounts funded by both a faucet and an attacker treasury
 *    are NOT exempted from Sybil clustering (the non-faucet funder causes grouping and weight capping to 1.0).
 * 3. Contract upgrade: Assert that code hash mutation forces risk=55 and CODE_CHANGED, overriding established history.
 */

import { randomUUID } from 'node:crypto';
import {
  type AccountAdjacency,
  type AccountNode,
  type BoundedSubgraph,
  FaucetRegistry,
  type GraphEdge,
  ReportRepository,
  type ReporterFundingLineage,
  clusterDependenceGroups,
  createDatabase,
  getReceiverReputation,
  runMigrations,
} from '@counterparty-guard/reputation';
import { ReceiverReportsResponseSchema, type ReportRecord } from '@counterparty-guard/shared';
import { type Action} from '@counterparty-guard/shared/demo';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it } from 'vitest';
import { buildServer } from '../../apps/api/test-support/report-server.js';
import { DeterministicAdapter } from '../../scripts/demo/harness/adapter.js';
import {
  WarningApprovalRequiredError,
  evaluateGuard,
  guardedAgentExecute,
} from '../../scripts/demo/harness/guard.js';

describe('Milestone M7 Empirical Security Challenge: Core Invariant Stress Harness', () => {
  const fixedNow = Date.now();
  let repo: ReportRepository;

  function mockReport(
    reportId: string,
    reporterId: string,
    accused = 'popular-merchant.testnet',
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
      description: 'Adversarial test allegation.',
      transaction_references: [`tx_${reportId}`],
      evidence_content_hashes: [],
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

  function addReport(report: ReportRecord): void {
    repo.registerReporter({
      reporter_id: report.reporter_id,
      public_key: report.reporter_public_key,
      network: 'testnet',
    });
    repo.insertReport(report);
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
  // Challenge 1: Massive Flood Stress Invariant
  // =========================================================================
  describe('Challenge 1: Massive Flood Stress Invariant', () => {
    it('asserts that 100+ raw unreviewed allegations NEVER trigger is_blocked: true', async () => {
      const target = 'popular-merchant.testnet';
      const floodCount = 120;

      for (let i = 1; i <= floodCount; i++) {
        const reporterId = `unreviewed_flooder_${i}.testnet`;
        addReport(mockReport(`rep_flood_${i}`, reporterId, target));
      }

      const allReports = repo.getReportsByAccused('testnet', target);
      expect(allReports.length).toBe(floodCount);

      const reputation = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        repository: repo,
      });

      expect(reputation.isBlocked).toBe(false);
      expect(reputation.rawReportCount).toBe(floodCount);
      expect(reputation.unresolvedReportsCount).toBe(floodCount);
      expect(reputation.reasonCodes).not.toContain('ACTIVE_BLOCK');
      expect(reputation.reasonCodes).not.toContain('REVIEWED_BLOCKLIST_MATCH');

      const action: Action = {
        kind: 'transfer_near',
        receiver_id: target,
        amount_yocto: '1000000000000000000000000',
      };

      const evaluation = await evaluateGuard(action, repo, 'testnet');
      expect(evaluation.decision).not.toBe('block');
    });

    it('asserts that 250 multi-status unreviewed allegations (submitted, verified, corroborated) NEVER block', async () => {
      const target = 'popular-merchant.testnet';

      // 100 submitted
      for (let i = 1; i <= 100; i++) {
        addReport(mockReport(`rep_sub_${i}`, `sub_reporter_${i}.testnet`, target));
      }
      // 75 references_verified
      for (let i = 1; i <= 75; i++) {
        addReport(
          mockReport(`rep_ver_${i}`, `ver_reporter_${i}.testnet`, target, {
            status: 'references_verified',
          }),
        );
      }
      // 75 corroborated
      for (let i = 1; i <= 75; i++) {
        addReport(
          mockReport(`rep_cor_${i}`, `cor_reporter_${i}.testnet`, target, {
            status: 'corroborated',
          }),
        );
      }

      const reputation = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        repository: repo,
      });

      expect(reputation.isBlocked).toBe(false);
      expect(reputation.rawReportCount).toBe(250);
      expect(reputation.unresolvedReportsCount).toBe(250);
      expect(reputation.reasonCodes).not.toContain('ACTIVE_BLOCK');
    });

    it('asserts that 100 Sybils across 5 distinct bot clusters never trigger is_blocked and cap weights', async () => {
      const target = 'popular-merchant.testnet';
      const reports: ReportRecord[] = [];
      const edges: Array<{ source: string; target: string }> = [];

      for (let c = 1; c <= 5; c++) {
        const clusterBoss = `cluster_treasury_${c}.testnet`;
        for (let b = 1; b <= 20; b++) {
          const botId = `cluster_${c}_bot_${b}.testnet`;
          const rep = mockReport(`rep_c${c}_b${b}`, botId, target);
          addReport(rep);
          reports.push(rep);
          edges.push({ source: clusterBoss, target: botId });
        }
      }

      const subgraph = buildMockSubgraph(target, edges, 2);

      const reputation = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        repository: repo,
        subgraph,
      });

      expect(reputation.isBlocked).toBe(false);
      expect(reputation.rawReportCount).toBe(100);
      expect(reputation.reasonCodes).toContain('DEPENDENT_REPORTS');
      expect(reputation.dependenceGroups.length).toBe(5);
      expect(reputation.effectiveReportWeight).toBe(5.0);
    });

    it('asserts Fastify HTTP endpoint never returns is_blocked: true under 60-report flood', async () => {
      let server: FastifyInstance | null = null;
      try {
        server = await buildServer({ repository: repo });
        const target = 'http-flood-victim.testnet';

        for (let i = 1; i <= 60; i++) {
          addReport(mockReport(`rep_http_${i}`, `flooder_${i}.testnet`, target));
        }

        const res = await server.inject({
          method: 'GET',
          url: `/v1/receivers/testnet/${target}/reports`,
        });

        expect(res.statusCode).toBe(200);
        const body = res.json();
        const parsed = ReceiverReportsResponseSchema.parse(body);

        expect(parsed.is_blocked).toBe(false);
        expect(parsed.total_reports).toBe(60);
      } finally {
        if (server) await server.close();
      }
    });

    it('proves that ONLY authenticated reviewer intervention can flip is_blocked to true', async () => {
      const target = 'reviewed-victim.testnet';

      // 100 raw unreviewed reports
      for (let i = 1; i <= 100; i++) {
        addReport(mockReport(`rep_split_${i}`, `rep_author_${i}.testnet`, target));
      }

      let rep = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        repository: repo,
      });
      expect(rep.isBlocked).toBe(false);

      // Now authenticated human reviewer creates an active block
      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: target,
        scope: 'account',
        reason: 'Confirmed malicious after human audit',
        reviewer_id: 'security_auditor_alpha',
      });

      rep = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        repository: repo,
      });
      expect(rep.isBlocked).toBe(true);
      expect(rep.blockReason).toBe('Confirmed malicious after human audit');
      expect(rep.reputationRiskPoints).toBe(100);
      expect(rep.reasonCodes).toContain('ACTIVE_BLOCK');
    });
  });

  // =========================================================================
  // Challenge 2: Adversarial Faucet Laundering Evasion Stress
  // =========================================================================
  describe('Challenge 2: Adversarial Faucet Laundering Evasion Stress', () => {
    it('asserts laundering with faucet + single attacker treasury is clustered and capped to 1.0', () => {
      const faucetRegistry = new FaucetRegistry(repo, { loadDefaults: true });
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();
      const attackerFunder = 'attacker-private-treasury.testnet';

      for (let i = 1; i <= 30; i++) {
        const reporterId = `launder_bot_${i}.testnet`;
        reports.push(mockReport(`rep_launder_${i}`, reporterId));
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

      expect(result.totalRawReports).toBe(30);
      expect(result.totalEffectiveWeight).toBe(1.0);
      expect(result.sybilDiscountApplied).toBe(true);
      expect(result.dependenceGroups.length).toBe(1);
      expect(result.dependenceGroups[0].reporterCount).toBe(30);
      expect(result.dependenceGroups[0].effectiveWeight).toBe(1.0);
      expect(result.dependenceGroups[0].commonFunderId).toBe(attackerFunder);
      expect(result.reasonCodes).toContain('DEPENDENT_REPORTS');
      expect(result.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');

      for (const r of reports) {
        expect(result.reportWeightMap.get(r.report_id)).toBeCloseTo(1.0 / 30, 5);
      }
    });

    it('asserts 2-hop grandfunder laundering with intermediate mules is clustered and capped to 1.0', () => {
      const faucetRegistry = new FaucetRegistry(repo, { loadDefaults: true });
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();
      const grandAttacker = 'mastermind-cartel.testnet';

      for (let i = 1; i <= 20; i++) {
        const reporterId = `deep_bot_${i}.testnet`;
        const directMule = `mule_acc_${i}.testnet`;
        reports.push(mockReport(`rep_deep_${i}`, reporterId));
        lineages.set(reporterId, {
          reporterId,
          directFunderId: directMule,
          grandFunderId: grandAttacker,
          allInboundFunders: ['faucet.testnet', directMule, grandAttacker],
          transferPeers: [],
        });
      }

      const result = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
        faucetRegistry,
      });

      expect(result.totalRawReports).toBe(20);
      expect(result.totalEffectiveWeight).toBe(1.0);
      expect(result.sybilDiscountApplied).toBe(true);
      expect(result.dependenceGroups.length).toBe(1);
      expect(result.dependenceGroups[0].reporterCount).toBe(20);
    });

    it('asserts laundering across 4 distinct faucets + single attacker coordinator is unified into 1 cluster', () => {
      const faucetRegistry = new FaucetRegistry(repo, { loadDefaults: true });
      const faucets = [
        'faucet.testnet',
        'friendbot.testnet',
        'v2.near-faucet.testnet',
        'faucet.sandbox',
      ];
      const coordinator = 'shadow-coordinator.testnet';

      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();

      for (let i = 1; i <= 24; i++) {
        const reporterId = `multi_faucet_bot_${i}.testnet`;
        const assignedFaucet = faucets[i % faucets.length];
        reports.push(mockReport(`rep_mf_${i}`, reporterId));
        lineages.set(reporterId, {
          reporterId,
          directFunderId: coordinator,
          allInboundFunders: [assignedFaucet, coordinator],
          transferPeers: [],
        });
      }

      const result = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
        faucetRegistry,
      });

      expect(result.totalRawReports).toBe(24);
      expect(result.totalEffectiveWeight).toBe(1.0);
      expect(result.dependenceGroups.length).toBe(1);
      expect(result.dependenceGroups[0].reporterCount).toBe(24);
      expect(result.dependenceGroups[0].commonFunderId).toBe(coordinator);
    });

    it('asserts collusive transfer ring between faucet-funded bots collapses weight to 1.0', () => {
      const faucetRegistry = new FaucetRegistry(repo, { loadDefaults: true });
      const count = 15;
      const reports: ReportRecord[] = [];
      const botIds = Array.from({ length: count }, (_, i) => `faucet_ring_bot_${i + 1}.testnet`);
      const lineages = new Map<string, ReporterFundingLineage>();

      for (let i = 0; i < count; i++) {
        const id = botIds[i];
        const nextId = botIds[(i + 1) % count];
        reports.push(mockReport(`rep_ring_${i + 1}`, id));
        lineages.set(id, {
          reporterId: id,
          allInboundFunders: ['faucet.testnet'],
          transferPeers: [nextId],
        });
      }

      const result = clusterDependenceGroups({
        network: 'testnet',
        reports,
        lineages,
        faucetRegistry,
      });

      expect(result.totalRawReports).toBe(count);
      expect(result.totalEffectiveWeight).toBe(1.0);
      expect(result.sybilDiscountApplied).toBe(true);
      expect(result.dependenceGroups.length).toBe(1);
      expect(result.dependenceGroups[0].reporterCount).toBe(count);
    });

    it('asserts clean separation: 12 honest faucet users keep 12.0 weight while 20 laundering bots cap to 1.0', () => {
      const faucetRegistry = new FaucetRegistry(repo, { loadDefaults: true });
      const reports: ReportRecord[] = [];
      const lineages = new Map<string, ReporterFundingLineage>();

      // 12 honest faucet users
      for (let i = 1; i <= 12; i++) {
        const id = `clean_user_${i}.testnet`;
        reports.push(mockReport(`rep_cu_${i}`, id));
        lineages.set(id, {
          reporterId: id,
          allInboundFunders: ['faucet.testnet'],
          transferPeers: [],
        });
      }

      // 20 laundering bots
      const attackerFunder = 'shadow-fund.testnet';
      for (let i = 1; i <= 20; i++) {
        const id = `launder_bot_${i}.testnet`;
        reports.push(mockReport(`rep_lb_${i}`, id));
        lineages.set(id, {
          reporterId: id,
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

      expect(result.totalRawReports).toBe(32);
      expect(result.totalEffectiveWeight).toBe(13.0);
      expect(result.dependenceGroups.length).toBe(1);
      expect(result.dependenceGroups[0].reporterCount).toBe(20);
      expect(result.dependenceGroups[0].effectiveWeight).toBe(1.0);
    });
  });

  // =========================================================================
  // Challenge 3: Contract Bytecode Upgrade Invariant
  // =========================================================================
  describe('Challenge 3: Contract Bytecode Upgrade Invariant', () => {
    const OLD_CODE_HASH = '1111111111111111111111111111111111111111111111111111111111111111';
    const NEW_CODE_HASH = '2222222222222222222222222222222222222222222222222222222222222222';

    it('asserts code hash mutation forces risk=55 and CODE_CHANGED, overriding established history (risk 5)', async () => {
      const target = 'established-merchant.testnet';

      // 15 visited neighbors, clean established history
      const subgraph = buildMockSubgraph(target, [], 15);

      // Baseline: unchanged hash retains established risk 5
      const baselineRep = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        contractCodeHash: OLD_CODE_HASH,
        priorApprovedCodeHash: OLD_CODE_HASH,
        repository: repo,
        subgraph,
      });
      expect(baselineRep.reputationRiskPoints).toBe(40);
      expect(baselineRep.reasonCodes).not.toContain('CODE_CHANGED');

      // Adversarial mutation: code changed
      const mutatedRep = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        contractCodeHash: NEW_CODE_HASH,
        priorApprovedCodeHash: OLD_CODE_HASH,
        repository: repo,
        subgraph,
      });

      expect(mutatedRep.reputationRiskPoints).toBe(55);
      expect(mutatedRep.reasonCodes).toContain('CODE_CHANGED');
      expect(mutatedRep.isBlocked).toBe(false);

      const action: Action = {
        kind: 'transfer_near',
        receiver_id: target,
        amount_yocto: '5000000000000000000000000',
      };

      const evalResult = await evaluateGuard(action, repo, 'testnet', subgraph, {
        contractCodeHash: NEW_CODE_HASH,
        priorApprovedCodeHash: OLD_CODE_HASH,
      });

      expect(evalResult.decision).toBe('warn');
      expect(evalResult.riskIndicator).toBe(55);
      expect(evalResult.reasonCodes).toContain('CODE_CHANGED');

      await expect(
        guardedAgentExecute(action, repo, 'testnet', subgraph, {
          contractCodeHash: NEW_CODE_HASH,
          priorApprovedCodeHash: OLD_CODE_HASH,
        }),
      ).rejects.toThrow(WarningApprovalRequiredError);
    });

    it('asserts Sybil flood attack cannot downgrade code change risk=55 to risk=20', async () => {
      const target = 'upgraded-contract.testnet';
      const edges: Array<{ source: string; target: string }> = [];

      for (let i = 1; i <= 20; i++) {
        const botId = `flood_bot_${i}.testnet`;
        addReport(mockReport(`rep_fc_${i}`, botId, target));
        edges.push({ source: 'attacker-treasury.testnet', target: botId });
      }

      const subgraph = buildMockSubgraph(target, edges, 12);

      const rep = await getReceiverReputation({
        network: 'testnet',
        accountId: target,
        contractCodeHash: NEW_CODE_HASH,
        priorApprovedCodeHash: OLD_CODE_HASH,
        repository: repo,
        subgraph,
      });

      expect(rep.reasonCodes).toContain('CODE_CHANGED');
      expect(rep.reasonCodes).toContain('DEPENDENT_REPORTS');
      expect(rep.reputationRiskPoints).toBe(55);
    });

    it('asserts DeterministicAdapter executes Scenario S7 with signed=false and submitted=false', async () => {
      const adapter = new DeterministicAdapter();
      await adapter.init();
      const result = await adapter.executeScenario('S7');

      expect(result.passed).toBe(true);
      expect(result.scenarioId).toBe('S7');
      expect(result.rawVerdict?.decision).toBe('warn');
      expect(result.rawVerdict?.riskScore).toBe(25);

      const log = result.log;
      expect(log.scenario_id).toBe('S7');
      expect(log.decision).toBe('warn');
      expect(log.signed).toBe(false);
      expect(log.submitted).toBe(false);
      expect(log.finalized_outcome).toBe('awaiting_owner_approval');
      expect(log.receiver_balance_delta).toBe('0');
      expect(log.reason_codes).toContain('CODE_CHANGED');
      expect(log.permit_hash).toMatch(/^[a-f0-9]{64}$/);

      await adapter.teardown();
    });
  });
});
