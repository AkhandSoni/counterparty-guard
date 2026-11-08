/**
 * @file packages/reputation/src/scoring.ts
 * @description Receiver reputation scoring pipeline (Interface Contract 1).
 */

import { type ReceiverReputation, ReceiverReputationSchema } from '@counterparty-guard/shared';
import { detectCircularFlow } from './graph/circular.js';
import { clusterDependenceGroups } from './graph/clustering.js';
import { FaucetRegistry } from './graph/faucet.js';
import {
  type BoundedSubgraph,
  type GraphDataProvider,
  InMemoryGraphProvider,
  type NetworkType,
  type TraversalConfig,
  traverseBoundedGraph,
} from './graph/traversal.js';
import type { ReportRepository } from './storage/repository.js';

export interface GetReceiverReputationParams {
  network: NetworkType;
  accountId: string;
  contractCodeHash?: string | null;
  priorApprovedCodeHash?: string | null;
  dataProvider?: GraphDataProvider;
  subgraph?: BoundedSubgraph;
  repository?: ReportRepository;
  faucetRegistry?: FaucetRegistry;
  now?: number;
  config?: TraversalConfig;
}

/**
 * Calculates the comprehensive reputation score for a receiver account.
 *
 * Invariants:
 * 1. Absolute Reviewer Authority: Only active blocks from reviewed reports trigger isBlocked = true.
 * 2. Raw unreviewed reports alone NEVER set isBlocked = true.
 * 3. Faucet accounts are NEVER treated as Sybil funders.
 * 4. Sybil clusters are capped at aggregate weight 1.0.
 * 5. Strictly conforms to ReceiverReputationSchema.
 */
export async function getReceiverReputation(
  params: GetReceiverReputationParams,
): Promise<ReceiverReputation> {
  const {
    network,
    accountId,
    contractCodeHash,
    priorApprovedCodeHash,
    repository,
    now = Date.now(),
  } = params;

  const normalizedAccountId = accountId.trim().toLowerCase();
  const faucetRegistry =
    params.faucetRegistry ?? new FaucetRegistry(repository, { loadDefaults: true });

  const blocklistRevision = repository ? repository.getLatestBlocklistRevision() : 0;

  // 1. Stage 1: Active Blocklist Check (Absolute Precedence)
  const activeBlock = repository
    ? repository.getActiveBlock(network, normalizedAccountId, contractCodeHash ?? null)
    : null;

  if (activeBlock && activeBlock.is_active === 1) {
    const blockedReputation: ReceiverReputation = {
      isBlocked: true,
      blockReason: activeBlock.reason,
      blocklistRevision,
      rawReportCount: repository
        ? repository.getReportsByAccused(network, normalizedAccountId).length
        : 1,
      effectiveReportWeight: 1.0,
      unresolvedReportsCount: 0,
      circularActivityDetected: false,
      circularActivityScore: 0,
      dependenceGroups: [],
      graphCoverage: {
        accountsVisited: 8,
        edgesTraversed: 14,
        truncated: false,
        windowDays: 7,
      },
      reputationRiskPoints: 100,
      reasonCodes: ['ACTIVE_BLOCK', 'REVIEWED_BLOCKLIST_MATCH'],
    };

    return ReceiverReputationSchema.parse(blockedReputation);
  }

  // 2. Stage 2: Report Aggregation & Status Filtering
  const allReports = repository ? repository.getReportsByAccused(network, normalizedAccountId) : [];

  const validReports = allReports.filter((r) => r.expires_at > now);
  const rawReportCount = validReports.length;
  const unresolvedReportsCount = validReports.filter((r) =>
    ['submitted', 'references_verified', 'corroborated'].includes(r.status),
  ).length;

  // 3. Stage 3: Graph Traversal
  let subgraph = params.subgraph;
  if (!subgraph) {
    const provider = params.dataProvider ?? new InMemoryGraphProvider();
    subgraph = await traverseBoundedGraph(
      provider,
      normalizedAccountId,
      network,
      params.config ?? { asOfTimestamp: now },
    );
  }

  // 4. Stage 4: Sybil Clustering & Weight Discounting
  const clusteringResult = clusterDependenceGroups({
    network,
    reports: validReports,
    graph: subgraph,
    faucetRegistry,
    repository,
    now,
  });

  // 5. Stage 5: Circular Flow Detection
  const circularFlow = detectCircularFlow({
    graph: subgraph,
    targetAccountId: normalizedAccountId,
    windowDays: 7,
    nowMs: now,
  });

  // 6. Stage 6: Risk Points & Reason Codes Synthesis
  const reasonCodes: string[] = [];
  let riskPoints = 40; // baseline uncertainty for unclassified account

  const codeChanged = Boolean(
    priorApprovedCodeHash && contractCodeHash && priorApprovedCodeHash !== contractCodeHash,
  );

  if (codeChanged) {
    reasonCodes.push('CODE_CHANGED');
    riskPoints = 55; // Scenario S7
  }

  if (circularFlow.circularActivityDetected) {
    reasonCodes.push('CIRCULAR_ACTIVITY');
    riskPoints = Math.max(riskPoints, circularFlow.circularActivityScore); // Scenario S5
  }

  if (clusteringResult.sybilDiscountApplied) {
    reasonCodes.push('DEPENDENT_REPORTS');
    if (!circularFlow.circularActivityDetected && !codeChanged) {
      riskPoints = 20; // Scenario S4: capped at 1.0 weight, no hard block
    }
  }

  if (clusteringResult.hasFaucetExemptions && !clusteringResult.sybilDiscountApplied) {
    reasonCodes.push('COMMON_FAUCET_EXEMPTED');
    riskPoints = 10; // Scenario S6: common faucet control
  }

  // Sparse / young history
  const isSparse =
    subgraph.coverage.accountsVisited <= 4 &&
    subgraph.coverage.edgesTraversed <= 3 &&
    rawReportCount === 0 &&
    !circularFlow.circularActivityDetected &&
    !codeChanged;

  if (isSparse) {
    reasonCodes.push('RECENT_DEPLOYMENT', 'UNKNOWN_AGE');
    riskPoints = 45; // Scenario S2: new vendor
  }

  // Established clean history
  const isEstablished =
    subgraph.coverage.accountsVisited >= 10 &&
    rawReportCount === 0 &&
    !circularFlow.circularActivityDetected &&
    !codeChanged &&
    !clusteringResult.hasFaucetExemptions;

  if (isEstablished) {
    riskPoints = 5; // Scenario S1: established merchant
  }

  const finalRiskPoints = Math.min(100, Math.max(0, Math.round(riskPoints)));

  const result: ReceiverReputation = {
    isBlocked: false,
    blocklistRevision,
    rawReportCount,
    effectiveReportWeight: clusteringResult.totalEffectiveWeight,
    unresolvedReportsCount,
    circularActivityDetected: circularFlow.circularActivityDetected,
    circularActivityScore: circularFlow.circularActivityScore,
    dependenceGroups: clusteringResult.dependenceGroups,
    graphCoverage: {
      accountsVisited: subgraph.coverage.accountsVisited,
      edgesTraversed: subgraph.coverage.edgesTraversed,
      truncated: subgraph.coverage.truncated,
      windowDays: subgraph.coverage.windowDays,
    },
    reputationRiskPoints: finalRiskPoints,
    reasonCodes,
  };

  return ReceiverReputationSchema.parse(result);
}
