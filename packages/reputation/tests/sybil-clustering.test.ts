import type { ReportRecord } from '@counterparty-guard/shared';
import { describe, expect, it } from 'vitest';
import { type ReporterFundingLineage, clusterDependenceGroups } from '../src/graph/clustering.js';
import {
  DEFAULT_FAUCET_EXEMPTIONS,
  FaucetRegistry,
  isFaucetExempted,
} from '../src/graph/faucet.js';
import { createDatabase } from '../src/storage/db.js';
import { runMigrations } from '../src/storage/migrations.js';
import { ReportRepository } from '../src/storage/repository.js';

describe('Milestone M4: Sybil Clustering, Faucets & Weight Capping (clustering.ts & faucet.ts)', () => {
  const faucetRegistry = new FaucetRegistry();

  function mockReport(
    reportId: string,
    reporterId: string,
    accused = 'target.testnet',
  ): ReportRecord {
    return {
      report_id: reportId,
      network: 'testnet',
      accused_account_id: accused,
      reporter_id: reporterId,
      reporter_public_key: 'ed25519:6E8nnukpNm466w7mUo1k74mZvd7qQ8b5QG41u16wG5r3',
      category: 'wash_trading',
      description: 'Test allegation',
      transaction_references: [],
      evidence_content_hashes: [],
      contract_code_hash: null,
      status: 'submitted',
      issued_at: 1700000000000,
      expires_at: 1700086400000,
      nonce: `nonce_${reportId}`,
      signature: 'ed25519:test_sig',
      dependence_group_id: null,
      created_at: 1700000000000,
    };
  }

  it('S4 Requirement: 20 Sybil accounts sharing non-faucet funder are capped to aggregate weight 1.0', () => {
    const reports: ReportRecord[] = [];
    const lineages = new Map<string, ReporterFundingLineage>();

    for (let i = 1; i <= 20; i++) {
      const reporterId = `sybil_${i}.testnet`;
      const reportId = `rep_${i}`;
      reports.push(mockReport(reportId, reporterId));

      lineages.set(reporterId, {
        reporterId,
        directFunderId: 'attacker-treasury.testnet',
        grandFunderId: 'master-mind.testnet',
        allInboundFunders: ['attacker-treasury.testnet', 'master-mind.testnet'],
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
    // Group weight capping invariant: aggregate weight is exactly 1.0
    expect(result.totalEffectiveWeight).toBe(1.0);
    expect(result.sybilDiscountApplied).toBe(true);
    expect(result.sybilDiscountAmount).toBe(19.0);
    expect(result.dependenceGroups.length).toBe(1);
    expect(result.dependenceGroups[0].reporterCount).toBe(20);
    expect(result.dependenceGroups[0].effectiveWeight).toBe(1.0);
    expect(result.dependenceGroups[0].commonFunderId).toBe('attacker-treasury.testnet');
    expect(result.dependenceGroups[0].faucetExempted).toBe(false);
    expect(result.reasonCodes).toContain('DEPENDENT_REPORTS');

    // Pro-rata distribution: 1.0 / 20 = 0.05 per report
    for (let i = 1; i <= 20; i++) {
      expect(result.reportWeightMap.get(`rep_${i}`)).toBeCloseTo(0.05);
    }
  });

  it('S6 Requirement: accounts sharing testnet faucet are exempted and retain full individual weights', () => {
    const reports: ReportRecord[] = [];
    const lineages = new Map<string, ReporterFundingLineage>();

    for (let i = 1; i <= 5; i++) {
      const reporterId = `legit_user_${i}.testnet`;
      const reportId = `legit_rep_${i}`;
      reports.push(mockReport(reportId, reporterId));

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

    expect(result.totalRawReports).toBe(5);
    // Retain full individual weights: 5 * 1.0 = 5.0
    expect(result.totalEffectiveWeight).toBe(5.0);
    expect(result.sybilDiscountApplied).toBe(false);
    expect(result.dependenceGroups.length).toBe(0); // No Sybil clusters formed
    expect(result.hasFaucetExemptions).toBe(true);
    expect(result.reasonCodes).toContain('COMMON_FAUCET_EXEMPTED');
    expect(result.reasonCodes).not.toContain('DEPENDENT_REPORTS');

    for (let i = 1; i <= 5; i++) {
      expect(result.reportWeightMap.get(`legit_rep_${i}`)).toBe(1.0);
    }
  });

  it('correctly partitions multiple independent clusters and unclustered singletons', () => {
    const reports: ReportRecord[] = [];
    const lineages = new Map<string, ReporterFundingLineage>();

    // Cluster 1: 10 Sybils funded by funder-alpha.testnet
    for (let i = 1; i <= 10; i++) {
      const reporterId = `alpha_${i}.testnet`;
      reports.push(mockReport(`rep_alpha_${i}`, reporterId));
      lineages.set(reporterId, {
        reporterId,
        allInboundFunders: ['funder-alpha.testnet'],
        transferPeers: [],
      });
    }

    // Cluster 2: 5 Sybils funded by funder-beta.testnet
    for (let i = 1; i <= 5; i++) {
      const reporterId = `beta_${i}.testnet`;
      reports.push(mockReport(`rep_beta_${i}`, reporterId));
      lineages.set(reporterId, {
        reporterId,
        allInboundFunders: ['funder-beta.testnet'],
        transferPeers: [],
      });
    }

    // 2 independent reporters
    for (let i = 1; i <= 2; i++) {
      const reporterId = `indep_${i}.testnet`;
      reports.push(mockReport(`rep_indep_${i}`, reporterId));
      lineages.set(reporterId, {
        reporterId,
        allInboundFunders: [`indep_funder_${i}.testnet`],
        transferPeers: [],
      });
    }

    const result = clusterDependenceGroups({
      network: 'testnet',
      reports,
      lineages,
      faucetRegistry,
    });

    expect(result.totalRawReports).toBe(17);
    // Cluster 1 (1.0) + Cluster 2 (1.0) + Indep 1 (1.0) + Indep 2 (1.0) = 4.0
    expect(result.totalEffectiveWeight).toBe(4.0);
    expect(result.sybilDiscountApplied).toBe(true);
    expect(result.dependenceGroups.length).toBe(2);

    // Each alpha report has 1.0 / 10 = 0.1
    expect(result.reportWeightMap.get('rep_alpha_1')).toBeCloseTo(0.1);
    // Each beta report has 1.0 / 5 = 0.2
    expect(result.reportWeightMap.get('rep_beta_1')).toBeCloseTo(0.2);
    // Each independent report retains 1.0
    expect(result.reportWeightMap.get('rep_indep_1')).toBe(1.0);
    expect(result.reportWeightMap.get('rep_indep_2')).toBe(1.0);
  });

  it('clusters reporters via direct transfers in 7-day window without known funder', () => {
    const reports: ReportRecord[] = [
      mockReport('rep_peer_1', 'peer_1.testnet'),
      mockReport('rep_peer_2', 'peer_2.testnet'),
    ];

    const lineages = new Map<string, ReporterFundingLineage>([
      [
        'peer_1.testnet',
        {
          reporterId: 'peer_1.testnet',
          allInboundFunders: [],
          transferPeers: ['peer_2.testnet'],
        },
      ],
      [
        'peer_2.testnet',
        {
          reporterId: 'peer_2.testnet',
          allInboundFunders: [],
          transferPeers: ['peer_1.testnet'],
        },
      ],
    ]);

    const result = clusterDependenceGroups({
      network: 'testnet',
      reports,
      lineages,
      faucetRegistry,
    });

    expect(result.dependenceGroups.length).toBe(1);
    expect(result.totalEffectiveWeight).toBe(1.0);
    expect(result.reportWeightMap.get('rep_peer_1')).toBe(0.5);
    expect(result.reportWeightMap.get('rep_peer_2')).toBe(0.5);
  });

  it('verifies static seed exemptions and repository database synchronization', () => {
    const db = createDatabase({ path: ':memory:' });
    runMigrations(db);
    const repo = new ReportRepository(db);

    // Test static exemptions
    expect(isFaucetExempted('faucet.testnet', 'testnet', repo)).toBe(true);
    expect(isFaucetExempted('testnet', 'testnet', repo)).toBe(true);
    expect(isFaucetExempted('v2.near-faucet.testnet', 'testnet', repo)).toBe(true);
    expect(isFaucetExempted('faucet.sandbox', 'sandbox', repo)).toBe(true);
    expect(isFaucetExempted('unknown-account.testnet', 'testnet', repo)).toBe(false);

    // Test custom exemption added to registry
    const customRegistry = new FaucetRegistry(repo);
    customRegistry.addExemption({
      exemptionId: 'custom-exemption-1',
      network: 'testnet',
      faucetAccountId: 'custom-community-faucet.testnet',
      label: 'Custom Community Faucet',
      exemptionType: 'faucet',
      isActive: true,
    });

    expect(customRegistry.isExempted('testnet', 'custom-community-faucet.testnet')).toBe(true);
    expect(customRegistry.isExempted('testnet', 'regular-user.testnet')).toBe(false);
  });
});
