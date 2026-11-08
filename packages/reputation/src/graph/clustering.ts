/**
 * @file packages/reputation/src/graph/clustering.ts
 * @description Sybil cluster detection, group weight capping, and pro-rata report discounting.
 */

import { createHash } from 'node:crypto';
import type { DependenceGroupSummary, ReportRecord } from '@counterparty-guard/shared';
import type { ReportRepository } from '../storage/repository.js';
import { FaucetRegistry } from './faucet.js';
import type { BoundedSubgraph, NetworkType } from './traversal.js';

export interface ReporterFundingLineage {
  reporterId: string;
  directFunderId?: string | null; // Hop 1 funder
  grandFunderId?: string | null; // Hop 2 funder
  allInboundFunders: string[]; // All funding sources within 2 hops
  transferPeers: string[]; // Transacted accounts in 7-day window
}

export interface ClusterDependenceGroupsOptions {
  network: NetworkType;
  reports: ReportRecord[];
  graph?: BoundedSubgraph;
  lineages?: Map<string, ReporterFundingLineage>;
  faucetRegistry?: FaucetRegistry;
  repository?: ReportRepository;
  now?: number;
}

export interface ClusteringResult {
  dependenceGroups: DependenceGroupSummary[];
  reportWeightMap: Map<string, number>; // reportId -> discounted effective weight
  reporterGroupMap: Map<string, string>; // reporterId -> groupId
  totalRawReports: number;
  totalEffectiveWeight: number;
  sybilDiscountApplied: boolean;
  sybilDiscountAmount: number; // totalRawReports - totalEffectiveWeight
  hasFaucetExemptions: boolean;
  reasonCodes: string[]; // e.g. ['DEPENDENT_REPORTS'], ['COMMON_FAUCET_EXEMPTED']
}

/**
 * Disjoint Set Union (Union-Find) with path compression and union by rank.
 */
export class DisjointSetUnion {
  private parent: Map<string, string> = new Map();
  private rank: Map<string, number> = new Map();

  public makeSet(item: string): void {
    if (!this.parent.has(item)) {
      this.parent.set(item, item);
      this.rank.set(item, 0);
    }
  }

  public find(item: string): string {
    const root = this.parent.get(item);
    if (!root) {
      this.makeSet(item);
      return item;
    }
    if (root === item) return item;
    const parentRoot = this.find(root);
    this.parent.set(item, parentRoot);
    return parentRoot;
  }

  public union(a: string, b: string): void {
    const rootA = this.find(a);
    const rootB = this.find(b);
    if (rootA === rootB) return;

    const rankA = this.rank.get(rootA) ?? 0;
    const rankB = this.rank.get(rootB) ?? 0;
    if (rankA < rankB) {
      this.parent.set(rootA, rootB);
    } else if (rankA > rankB) {
      this.parent.set(rootB, rootA);
    } else {
      this.parent.set(rootB, rootA);
      this.rank.set(rootA, rankA + 1);
    }
  }

  public getComponents(): Map<string, string[]> {
    const components = new Map<string, string[]>();
    for (const item of this.parent.keys()) {
      const root = this.find(item);
      const list = components.get(root) ?? [];
      list.push(item);
      components.set(root, list);
    }
    return components;
  }
}

/**
 * Generates a deterministic group ID given common funder or cluster members.
 */
export function generateGroupId(
  commonFunderId: string | null | undefined,
  members: string[],
): string {
  if (commonFunderId) {
    const hash = createHash('sha256')
      .update(`funder:${commonFunderId.toLowerCase()}`)
      .digest('hex')
      .slice(0, 16);
    return `group_funder_${hash}`;
  }
  const sorted = [...members].sort().join(',');
  const hash = createHash('sha256').update(`members:${sorted}`).digest('hex').slice(0, 16);
  return `group_cluster_${hash}`;
}

/**
 * Extracts reporter lineages from a BoundedSubgraph.
 */
export function extractLineagesFromGraph(
  reports: ReportRecord[],
  graph: BoundedSubgraph,
): Map<string, ReporterFundingLineage> {
  const lineages = new Map<string, ReporterFundingLineage>();

  for (const report of reports) {
    const reporterId = report.reporter_id.trim().toLowerCase();
    if (lineages.has(reporterId)) continue;

    const adj = graph.adjacency.get(reporterId);
    const inEdges = adj?.inEdges ?? [];
    const directFunders = Array.from(new Set(inEdges.map((e) => e.source.trim().toLowerCase())));

    const grandFundersSet = new Set<string>();
    for (const funder of directFunders) {
      const funderAdj = graph.adjacency.get(funder);
      if (funderAdj) {
        for (const e of funderAdj.inEdges) {
          grandFundersSet.add(e.source.trim().toLowerCase());
        }
      }
    }

    const allInboundFunders = Array.from(new Set([...directFunders, ...grandFundersSet]));

    const transferPeersSet = new Set<string>();
    if (adj) {
      for (const e of adj.inEdges) transferPeersSet.add(e.source.trim().toLowerCase());
      for (const e of adj.outEdges) transferPeersSet.add(e.target.trim().toLowerCase());
    }
    transferPeersSet.delete(reporterId);

    lineages.set(reporterId, {
      reporterId,
      directFunderId: directFunders[0] ?? null,
      grandFunderId: Array.from(grandFundersSet)[0] ?? null,
      allInboundFunders,
      transferPeers: Array.from(transferPeersSet),
    });
  }

  return lineages;
}

/**
 * Clusters reports into dependence groups, applies Sybil discounting, and caps group weights.
 */
export function clusterDependenceGroups(options: ClusterDependenceGroupsOptions): ClusteringResult {
  const { network, reports, graph, repository } = options;
  const faucetRegistry =
    options.faucetRegistry ?? new FaucetRegistry(repository, { loadDefaults: true });

  const lineages =
    options.lineages ??
    (graph ? extractLineagesFromGraph(reports, graph) : new Map<string, ReporterFundingLineage>());

  const dsu = new DisjointSetUnion();
  const reporterToReports = new Map<string, ReportRecord[]>();

  // 1. Initialize sets for each reporter
  for (const report of reports) {
    const repId = report.reporter_id.trim().toLowerCase();
    dsu.makeSet(repId);
    const existing = reporterToReports.get(repId) ?? [];
    existing.push(report);
    reporterToReports.set(repId, existing);
  }

  let observedFaucetInLineage = false;

  // 2. Correlate reporters via common non-faucet funders and transfers
  const nonFaucetFunderToFirstReporter = new Map<string, string>();

  for (const [reporterId, lineage] of lineages.entries()) {
    if (!reporterToReports.has(reporterId)) continue;

    // Check for faucet presence in lineage
    if (
      (lineage.directFunderId && faucetRegistry.isExempted(network, lineage.directFunderId)) ||
      (lineage.grandFunderId && faucetRegistry.isExempted(network, lineage.grandFunderId)) ||
      lineage.allInboundFunders.some((f) => faucetRegistry.isExempted(network, f))
    ) {
      observedFaucetInLineage = true;
    }

    // Filter out faucet-exempted funders
    const cleanFunders = faucetRegistry.filterNonFaucetAccounts(network, lineage.allInboundFunders);

    // Correlate by common non-faucet funder
    for (const funder of cleanFunders) {
      const priorReporter = nonFaucetFunderToFirstReporter.get(funder);
      if (priorReporter) {
        dsu.union(reporterId, priorReporter);
      } else {
        nonFaucetFunderToFirstReporter.set(funder, reporterId);
      }
    }

    // Correlate by direct transfers among reporters
    for (const peer of lineage.transferPeers) {
      if (reporterToReports.has(peer)) {
        dsu.union(reporterId, peer);
      }
    }
  }

  // 3. Extract connected components (dependence groups)
  const components = dsu.getComponents();
  const dependenceGroups: DependenceGroupSummary[] = [];
  const reportWeightMap = new Map<string, number>();
  const reporterGroupMap = new Map<string, string>();

  let totalEffectiveWeight = 0;
  let sybilDiscountApplied = false;

  for (const [, memberReporters] of components.entries()) {
    const clusterReports: ReportRecord[] = [];
    for (const repId of memberReporters) {
      const repReports = reporterToReports.get(repId) ?? [];
      clusterReports.push(...repReports);
    }
    if (clusterReports.length === 0) continue;

    const isMultiMember = memberReporters.length > 1;

    // Identify candidate common non-faucet funder if available
    let commonFunderId: string | undefined;
    if (isMultiMember) {
      for (const repId of memberReporters) {
        const lineage = lineages.get(repId);
        if (!lineage) continue;
        const cleanFunders = faucetRegistry.filterNonFaucetAccounts(
          network,
          lineage.allInboundFunders,
        );
        if (cleanFunders.length > 0) {
          commonFunderId = cleanFunders[0];
          break;
        }
      }
    }

    const groupId = isMultiMember
      ? generateGroupId(commonFunderId, memberReporters)
      : (clusterReports[0].dependence_group_id ?? `singleton_${memberReporters[0]}`);

    // Group Weight Capping Invariant: Aggregate weight is capped at at most 1.0
    const aggregateGroupWeight = Math.min(1.0, isMultiMember ? 1.0 : clusterReports.length * 1.0);

    // Pro-rata distribution across all reports in the group (1.0 / count)
    const perReportWeight =
      clusterReports.length > 0 ? aggregateGroupWeight / clusterReports.length : 0;

    for (const r of clusterReports) {
      reportWeightMap.set(r.report_id, perReportWeight);
      reporterGroupMap.set(r.reporter_id.trim().toLowerCase(), groupId);
    }

    totalEffectiveWeight += aggregateGroupWeight;

    if (isMultiMember) {
      sybilDiscountApplied = true;
      dependenceGroups.push({
        groupId,
        reporterCount: memberReporters.length,
        effectiveWeight: aggregateGroupWeight,
        commonFunderId,
        faucetExempted: false,
      });
    }
  }

  // Reason codes
  const reasonCodes: string[] = [];
  if (sybilDiscountApplied) {
    reasonCodes.push('DEPENDENT_REPORTS');
  }
  if (observedFaucetInLineage) {
    reasonCodes.push('COMMON_FAUCET_EXEMPTED');
  }

  const totalRawReports = reports.length;
  const sybilDiscountAmount = Math.max(0, totalRawReports - totalEffectiveWeight);

  const result: ClusteringResult = {
    dependenceGroups,
    reportWeightMap,
    reporterGroupMap,
    totalRawReports,
    totalEffectiveWeight,
    sybilDiscountApplied,
    sybilDiscountAmount,
    hasFaucetExemptions: observedFaucetInLineage,
    reasonCodes,
  };

  // Persist if repository provided
  if (repository) {
    persistDependenceGroups(repository, result, reports, network);
  }

  return result;
}

/**
 * Backward-compatible alias for clusterDependenceGroups.
 */
export function clusterReportsAndDiscount(
  reports: ReportRecord[],
  lineages: Map<string, ReporterFundingLineage>,
  options: {
    network: NetworkType;
    faucetRegistry?: FaucetRegistry;
    repository?: ReportRepository;
    now?: number;
  },
): ClusteringResult {
  return clusterDependenceGroups({
    network: options.network,
    reports,
    lineages,
    faucetRegistry: options.faucetRegistry,
    repository: options.repository,
    now: options.now,
  });
}

/**
 * Persists discovered dependence groups and updates report records in the repository.
 */
export function persistDependenceGroups(
  repo: ReportRepository,
  result: ClusteringResult,
  reports: ReportRecord[],
  network: NetworkType,
): void {
  const now = Date.now();

  for (const group of result.dependenceGroups) {
    repo.upsertDependenceGroup({
      group_id: group.groupId,
      network,
      common_funder_id: group.commonFunderId ?? null,
      faucet_exempted: group.faucetExempted ? 1 : 0,
      effective_weight: group.effectiveWeight,
      reporter_count: group.reporterCount,
      clustering_reason: group.commonFunderId
        ? 'COMMON_NON_FAUCET_FUNDER_2_HOPS'
        : 'HIGH_DENSITY_TRANSFER_CLUSTER',
      created_at: now,
      updated_at: now,
    });
  }

  // Update reports with assigned dependence_group_id
  for (const report of reports) {
    const normalizedRepId = report.reporter_id.trim().toLowerCase();
    const groupId = result.reporterGroupMap.get(normalizedRepId);
    if (groupId && groupId !== report.dependence_group_id && !groupId.startsWith('singleton_')) {
      repo.updateReportStatus(report.report_id, report.status, groupId);
      repo.addGroupMember(groupId, report.reporter_id, 'reporter', 1);
    }
  }
}
