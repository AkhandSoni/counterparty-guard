import { z } from 'zod';
import { accountIdSchema, amountSchema, timestampSchema, type ReputationProvider } from '@counterparty-guard/shared';
import { clusterDependenceGroups } from './graph/clustering.js';
import { detectCircularFlow } from './graph/circular.js';
import { InMemoryGraphProvider, traverseBoundedGraph, type GraphEdge } from './graph/traversal.js';
import type { ReportRepository } from './storage/repository.js';

const edgeSchema = z.object({ receipt_id: z.string().min(1), predecessor_id: accountIdSchema, receiver_id: accountIdSchema, amount_yocto: amountSchema, timestamp_ms: timestampSchema });
const graphSchema = z.object({ edges: z.array(edgeSchema).max(500) });
/** C's in-process adapter supplies bounded report/graph features to A's sole authorization scorer. */
export function createReputationProvider(repository: ReportRepository, clock: () => number = Date.now): ReputationProvider {
  return {
    async getReputation(network, accountId, evidence) {
      const now = clock();
      const retainedGraph = evidence.observations.find(observation => observation.kind === 'transfer_graph');
      const parsed = retainedGraph ? graphSchema.parse(retainedGraph.value) : { edges: [] };
      const edges: GraphEdge[] = parsed.edges.map(edge => ({ id: edge.receipt_id, source: edge.predecessor_id, target: edge.receiver_id, amountYocto: edge.amount_yocto, timestamp: edge.timestamp_ms, type: 'transfer' }));
      const graph = await traverseBoundedGraph(new InMemoryGraphProvider(edges), accountId, network, { asOfTimestamp: now });
      const reports = repository.getReportsByAccused(network, accountId).filter(report => report.expires_at > now && ['submitted', 'references_verified', 'corroborated'].includes(report.status) && (report.transaction_references.length > 0 || report.evidence_content_hashes.length > 0));
      const clustering = clusterDependenceGroups({ network, reports, graph, now });
      const circular = detectCircularFlow({ graph, targetAccountId: accountId, nowMs: now, windowDays: 7 });
      const blocks = repository.getActiveBlocks(network, accountId, now);
      return {
        network, account_id: accountId, blocklist_revision: String(repository.getLatestBlocklistRevision()), observed_at: now, available: true,
        active_blocks: blocks.map(block => ({ id: block.entry_id, network, account_id: accountId,
          code_identity: block.scope === 'account' ? null : block.contract_code_hash,
          expires_at: block.expires_at ?? Number.MAX_SAFE_INTEGER, reviewed_by: block.reviewer_id,
          evidence_refs: block.report_id ? [`report:${block.report_id}`] : [`review:${block.entry_id}`] })),
        unresolved_report_weight: Math.min(10, Math.ceil(clustering.totalEffectiveWeight)),
        dependent_report_groups: clustering.dependenceGroups.length,
        manipulation_score: circular.circularActivityDetected ? Math.min(30, Math.round(circular.circularActivityScore)) : 0,
        // Only labelled fixtures carry known independence. Live graph size alone earns no trust.
        independent_activity_credit: evidence.source_mode === 'fixture' && !circular.circularActivityDetected ? Math.min(15, evidence.independent_successful_counterparties) : 0,
        explanations: [...clustering.explanations, ...(circular.circularActivityDetected ? ['Circular successful-transfer features reduce activity confidence.'] : []), 'Live activity independence is conservative; shared funding/code alone supplies no ownership inference.'].slice(0, 32),
        coverage: { ...evidence.coverage, truncated: evidence.coverage.truncated || graph.coverage.truncated,
          complete: evidence.coverage.complete && !graph.coverage.truncated,
          notes: [...evidence.coverage.notes, ...(retainedGraph ? [] : ['No retained transfer graph; report relationships are unknown.'])].slice(0, 32) },
      };
    },
  };
}
