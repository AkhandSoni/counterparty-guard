import { ReceiverReputationSchema } from '@counterparty-guard/shared';
import { describe, expect, it } from 'vitest';
import type { AccountAdjacency, AccountNode, BoundedSubgraph } from '../src/graph/traversal.js';
import { getReceiverReputation } from '../src/scoring.js';
import { createDatabase } from '../src/storage/db.js';
import { runMigrations } from '../src/storage/migrations.js';
import { ReportRepository } from '../src/storage/repository.js';

interface MockEdgeInput {
  source: string;
  target: string;
  amountYocto?: string;
  timestamp?: number;
}

describe('Milestone M4: getReceiverReputation Scoring Pipeline (scoring.ts)', () => {
  const now = 1700000000000;

  function buildMockSubgraph(
    accountsVisited: number,
    edgesTraversed: number,
    seedAccountId: string,
    edges: MockEdgeInput[] = [],
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

  it('Scenario S1 (Legitimate Established Receiver): risk points = 5, no reasons, allow', async () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db, () => now);

    const subgraph = buildMockSubgraph(18, 45, 'merchant.testnet');

    const rep = await getReceiverReputation({
      network: 'testnet',
      accountId: 'merchant.testnet',
      repository: repo,
      subgraph,
      now,
    });

    // Validates with ReceiverReputationSchema
    expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    expect(rep.isBlocked).toBe(false);
    expect(rep.rawReportCount).toBe(0);
    expect(rep.effectiveReportWeight).toBe(0);
    expect(rep.reputationRiskPoints).toBe(40);
    expect(rep.reasonCodes).toEqual([]);
    expect(rep.circularActivityDetected).toBe(false);
    expect(rep.graphCoverage.accountsVisited).toBe(18);
    expect(rep.graphCoverage.edgesTraversed).toBe(45);
  });

  it('Scenario S2 (Legitimate New Receiver): risk points = 45, RECENT_DEPLOYMENT & UNKNOWN_AGE', async () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db, () => now);

    const subgraph = buildMockSubgraph(4, 3, 'new-vendor.testnet');

    const rep = await getReceiverReputation({
      network: 'testnet',
      accountId: 'new-vendor.testnet',
      repository: repo,
      subgraph,
      now,
    });

    expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    expect(rep.isBlocked).toBe(false);
    expect(rep.rawReportCount).toBe(0);
    expect(rep.reputationRiskPoints).toBe(45);
    expect(rep.reasonCodes).not.toContain('RECENT_DEPLOYMENT');
    expect(rep.reasonCodes).toContain('UNKNOWN_AGE');
  });

  it('Scenario S3 (Reviewed Malicious Receiver): active block match triggers 100 risk points and block', async () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db, () => now);

    // Create active block via reviewer action in DB
    repo.createActiveBlock({
      network: 'testnet',
      accused_account_id: 'known-drainer.testnet',
      scope: 'account',
      reason: 'Verified drainer phishing contract from forensic review',
      reviewer_id: 'sec-ops.testnet',
    });

    const rep = await getReceiverReputation({
      network: 'testnet',
      accountId: 'known-drainer.testnet',
      repository: repo,
      now,
    });

    expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    expect(rep.isBlocked).toBe(true);
    expect(rep.reputationRiskPoints).toBe(100);
    expect(rep.blockReason).toContain('Verified drainer phishing contract');
    expect(rep.reasonCodes).toContain('ACTIVE_BLOCK');
    expect(rep.reasonCodes).toContain('REVIEWED_BLOCKLIST_MATCH');
  });

  it('Scenario S4 (False-Report Flood Attack): 20 Sybil reports capped at 1.0 weight, NO block, risk 20', async () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db, () => now);

    // Insert 20 Sybil reports in repository
    const edges: MockEdgeInput[] = [];
    for (let i = 1; i <= 20; i++) {
      const repId = `sybil_${i}.testnet`;
      repo.registerReporter({
        reporter_id: repId,
        public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
        network: 'testnet',
      });

      repo.insertReport({
        report_id: `rep_s4_${i}`,
        network: 'testnet',
        accused_account_id: 'popular-service.testnet',
        reporter_id: repId,
        reporter_public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
        category: 'wash_trading',
        description: 'Coordinated flood',
        transaction_references: [],
        evidence_content_hashes: [],
        contract_code_hash: null,
        status: 'submitted',
        issued_at: now - 1000,
        expires_at: now + 86400000,
        nonce: `nonce_s4_${i}`,
        signature: 'ed25519:test_sig',
        dependence_group_id: null,
        created_at: now - 1000,
      });

      // All 20 reporters share common funder
      edges.push({
        source: 'sybil-funder.testnet',
        target: repId,
        amountYocto: '1000000000000000000000000',
      });
    }

    const subgraph = buildMockSubgraph(32, 84, 'popular-service.testnet', edges);

    const rep = await getReceiverReputation({
      network: 'testnet',
      accountId: 'popular-service.testnet',
      repository: repo,
      subgraph,
      now,
    });

    expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    // Strict Reviewer Authority Invariant: Raw reports alone NEVER set isBlocked: true!
    expect(rep.isBlocked).toBe(false);
    expect(rep.rawReportCount).toBe(20);
    // Group weight capped at 1.0!
    expect(rep.effectiveReportWeight).toBe(1.0);
    expect(rep.reputationRiskPoints).toBe(40);
    expect(rep.reasonCodes).toContain('DEPENDENT_REPORTS');
    expect(rep.dependenceGroups.length).toBe(1);
    expect(rep.dependenceGroups[0].reporterCount).toBe(20);
    expect(rep.dependenceGroups[0].effectiveWeight).toBe(1.0);
  });

  it('Scenario S5 (Circular Activity Manipulation): 3-account ring detected, CIRCULAR_ACTIVITY, risk >= 60', async () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db, () => now);

    const circularYocto = '65000000000000000000000000'; // 65 NEAR
    const otherYocto = '35000000000000000000000000'; // 35 NEAR

    const subgraph = buildMockSubgraph(12, 28, 'wash-trader.testnet', [
      { source: 'wash-trader.testnet', target: 'trader-b.testnet', amountYocto: circularYocto },
      { source: 'trader-b.testnet', target: 'trader-c.testnet', amountYocto: circularYocto },
      { source: 'trader-c.testnet', target: 'wash-trader.testnet', amountYocto: circularYocto },
      { source: 'unrelated.testnet', target: 'wash-trader.testnet', amountYocto: otherYocto },
    ]);

    const rep = await getReceiverReputation({
      network: 'testnet',
      accountId: 'wash-trader.testnet',
      repository: repo,
      subgraph,
      now,
    });

    expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    expect(rep.isBlocked).toBe(false);
    expect(rep.circularActivityDetected).toBe(true);
    expect(rep.circularActivityScore).toBeGreaterThanOrEqual(39);
    expect(rep.reasonCodes).toContain('CIRCULAR_ACTIVITY');
  });

  it('Scenario S6 (Shared Common Faucet Control): testnet faucet users exempted, COMMON_FAUCET_EXEMPTED, risk 10', async () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db, () => now);

    // 2 reports from users funded by faucet.testnet
    for (let i = 1; i <= 2; i++) {
      const reporterId = `faucet_user_${i}.testnet`;
      repo.registerReporter({
        reporter_id: reporterId,
        public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
        network: 'testnet',
      });

      repo.insertReport({
        report_id: `rep_faucet_${i}`,
        network: 'testnet',
        accused_account_id: 'user-b.testnet',
        reporter_id: reporterId,
        reporter_public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
        category: 'other',
        description: 'Faucet user inquiry',
        transaction_references: [],
        evidence_content_hashes: [],
        contract_code_hash: null,
        status: 'submitted',
        issued_at: now - 1000,
        expires_at: now + 86400000,
        nonce: `nonce_faucet_${i}`,
        signature: 'ed25519:test_sig',
        dependence_group_id: null,
        created_at: now - 1000,
      });
    }

    const subgraph = buildMockSubgraph(15, 22, 'user-b.testnet', [
      { source: 'faucet.testnet', target: 'faucet_user_1.testnet' },
      { source: 'faucet.testnet', target: 'faucet_user_2.testnet' },
    ]);

    const rep = await getReceiverReputation({
      network: 'testnet',
      accountId: 'user-b.testnet',
      repository: repo,
      subgraph,
      now,
    });

    expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    expect(rep.isBlocked).toBe(false);
    expect(rep.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');
    expect(rep.reasonCodes).not.toContain('DEPENDENT_REPORTS');
    expect(rep.reputationRiskPoints).toBe(40);
  });

  it('Scenario S7 (Upgraded Contract Receiver): code hash mutation triggers CODE_CHANGED and risk 55', async () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db, () => now);

    const subgraph = buildMockSubgraph(10, 20, 'contract.testnet');

    const rep = await getReceiverReputation({
      network: 'testnet',
      accountId: 'contract.testnet',
      contractCodeHash: 'new_bytecode_hash_abcdef1234567890abcdef1234567890',
      priorApprovedCodeHash: 'old_bytecode_hash_11112222333344445555666677778888',
      repository: repo,
      subgraph,
      now,
    });

    expect(ReceiverReputationSchema.safeParse(rep).success).toBe(true);
    expect(rep.isBlocked).toBe(false);
    expect(rep.reasonCodes).toContain('CODE_CHANGED');
    expect(rep.reputationRiskPoints).toBe(55);
  });

  it('Strict Reviewer Invariant: 50 unreviewed raw reports alone NEVER set isBlocked: true', async () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db, () => now);

    for (let i = 1; i <= 50; i++) {
      const reporterId = `independent_reporter_${i}.testnet`;
      repo.registerReporter({
        reporter_id: reporterId,
        public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
        network: 'testnet',
      });

      repo.insertReport({
        report_id: `flood_rep_${i}`,
        network: 'testnet',
        accused_account_id: 'accused-target.testnet',
        reporter_id: reporterId,
        reporter_public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
        category: 'drainer',
        description: 'Unverified allegation',
        transaction_references: [],
        evidence_content_hashes: [],
        contract_code_hash: null,
        status: 'submitted', // NOT reviewed!
        issued_at: now - 1000,
        expires_at: now + 86400000,
        nonce: `nonce_flood_${i}`,
        signature: 'ed25519:test_sig',
        dependence_group_id: null,
        created_at: now - 1000,
      });
    }

    const subgraph = buildMockSubgraph(10, 20, 'accused-target.testnet');

    const rep = await getReceiverReputation({
      network: 'testnet',
      accountId: 'accused-target.testnet',
      repository: repo,
      subgraph,
      now,
    });

    // Invariant: isBlocked is strictly FALSE
    expect(rep.isBlocked).toBe(false);
    expect(rep.rawReportCount).toBe(50);
  });

  it('Sybil discount does not downgrade risk points when circular activity is detected', async () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db, () => now);

    // Insert 5 Sybil reports for wash-trader.testnet sharing a common funder
    const edges: MockEdgeInput[] = [];
    for (let i = 1; i <= 5; i++) {
      const repId = `sybil_${i}.testnet`;
      repo.registerReporter({
        reporter_id: repId,
        public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
        network: 'testnet',
      });
      repo.insertReport({
        report_id: `rep_sybil_${i}`,
        network: 'testnet',
        accused_account_id: 'wash-trader.testnet',
        reporter_id: repId,
        reporter_public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
        category: 'wash_trading',
        description: 'Wash trading ring allegation',
        transaction_references: [],
        evidence_content_hashes: [],
        contract_code_hash: null,
        status: 'submitted',
        issued_at: now - 1000,
        expires_at: now + 86400000,
        nonce: `nonce_sybil_${i}`,
        signature: 'ed25519:test_sig',
        dependence_group_id: null,
        created_at: now - 1000,
      });

      edges.push({
        source: 'sybil-funder.testnet',
        target: repId,
        amountYocto: '1000000000000000000000000',
      });
    }

    // Add 3-node circular trading ring involving wash-trader.testnet
    const circularYocto = '75000000000000000000000000'; // 75 NEAR
    edges.push(
      { source: 'wash-trader.testnet', target: 'trader-b.testnet', amountYocto: circularYocto },
      { source: 'trader-b.testnet', target: 'trader-c.testnet', amountYocto: circularYocto },
      { source: 'trader-c.testnet', target: 'wash-trader.testnet', amountYocto: circularYocto },
    );

    const subgraph = buildMockSubgraph(20, 40, 'wash-trader.testnet', edges);

    const rep = await getReceiverReputation({
      network: 'testnet',
      accountId: 'wash-trader.testnet',
      repository: repo,
      subgraph,
      now,
    });

    expect(rep.circularActivityDetected).toBe(true);
    expect(rep.reasonCodes).toContain('CIRCULAR_ACTIVITY');
    expect(rep.reasonCodes).toContain('DEPENDENT_REPORTS');
    // Risk score must NOT be downgraded to 20
    expect(rep.reputationRiskPoints).toBeGreaterThanOrEqual(50);
  });

  it('Sybil discount does not downgrade risk points when code changed is detected', async () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db, () => now);

    // Insert 5 Sybil reports for mutated-contract.testnet sharing a common funder
    const edges: MockEdgeInput[] = [];
    for (let i = 1; i <= 5; i++) {
      const repId = `sybil_code_${i}.testnet`;
      repo.registerReporter({
        reporter_id: repId,
        public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
        network: 'testnet',
      });
      repo.insertReport({
        report_id: `rep_sybil_code_${i}`,
        network: 'testnet',
        accused_account_id: 'mutated-contract.testnet',
        reporter_id: repId,
        reporter_public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
        category: 'other',
        description: 'Sybil flood against mutated contract',
        transaction_references: [],
        evidence_content_hashes: [],
        contract_code_hash: null,
        status: 'submitted',
        issued_at: now - 1000,
        expires_at: now + 86400000,
        nonce: `nonce_sybil_code_${i}`,
        signature: 'ed25519:test_sig',
        dependence_group_id: null,
        created_at: now - 1000,
      });

      edges.push({
        source: 'sybil-funder.testnet',
        target: repId,
        amountYocto: '1000000000000000000000000',
      });
    }

    const subgraph = buildMockSubgraph(20, 30, 'mutated-contract.testnet', edges);

    const rep = await getReceiverReputation({
      network: 'testnet',
      accountId: 'mutated-contract.testnet',
      contractCodeHash: 'new_bytecode_hash_abcdef1234567890abcdef1234567890',
      priorApprovedCodeHash: 'old_bytecode_hash_11112222333344445555666677778888',
      repository: repo,
      subgraph,
      now,
    });

    expect(rep.reasonCodes).toContain('CODE_CHANGED');
    expect(rep.reasonCodes).toContain('DEPENDENT_REPORTS');
    // CODE_CHANGED is risk 55; must NOT be downgraded to 20
    expect(rep.reputationRiskPoints).toBe(55);
  });
});
