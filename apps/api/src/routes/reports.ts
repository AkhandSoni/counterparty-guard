import {
  type BoundedSubgraph,
  FaucetRegistry,
  type GraphDataProvider,
  ReportLifecycleEngine,
  ReportRepository,
  type ReporterFundingLineage,
  clusterDependenceGroups,
  getHttpStatusForIntakeErrorCode,
  traverseBoundedGraph,
  validateAndSubmitReport,
} from '@counterparty-guard/reputation';
import {
  type GetReportResponse,
  GetReportResponseSchema,
  type ReceiverReportsResponse,
  ReceiverReportsResponseSchema,
  ReviewReportRequestSchema,
  type ReviewReportResponse,
  ReviewReportResponseSchema,
  type SubmitReportResponse,
  SubmitReportResponseSchema,
} from '@counterparty-guard/shared';
import type { FastifyPluginAsync, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { ReportPluginContext } from '../app.js';
import { type ReviewerAuthConfig, extractReviewerContext } from '../auth/reviewer-auth.js';

export interface ReportsRouteOptions {
  repository: ReportRepository;
  now?: () => number;
  reviewerAuth?: ReviewerAuthConfig;
  authenticateReviewer?: (request: FastifyRequest) => { reviewer_id: string };
  invalidateReceiver?: ReportPluginContext['invalidateReceiver'];
  graphDataProvider?: GraphDataProvider;
  lineages?:
    | Map<string, ReporterFundingLineage>
    | ((account: string) => Map<string, ReporterFundingLineage>);
}

export const reportsRoutes: FastifyPluginAsync<ReportsRouteOptions> = async (fastify, options) => {
  const { repository } = options;
  const getNow = options.now || (() => Date.now());
  const lifecycleEngine = new ReportLifecycleEngine(repository);
  const faucetRegistry = new FaucetRegistry(repository, { loadDefaults: true });

  // 1. POST /v1/reports - Ingest signed report
  fastify.post('/v1/reports', async (request, reply) => {
    const now = getNow();
    const result = await validateAndSubmitReport(request.body, {
      storage: repository,
      now,
    });

    if (!result.success) {
      const statusCode = getHttpStatusForIntakeErrorCode(result.error.code);
      return reply.status(statusCode).send({
        error: result.error.code,
        message: result.error.message,
        details: result.error.details,
        timestamp: result.error.timestamp,
      });
    }

    const response: SubmitReportResponse = {
      report_id: result.data.report_id,
      status: 'submitted',
      issued_at: result.data.issued_at,
      expires_at: result.data.expires_at,
    };

    SubmitReportResponseSchema.parse(response);
    return reply.status(201).send(response);
  });

  // 2. GET /v1/reports/:id - Query report by ID
  fastify.get<{ Params: { id: string } }>('/v1/reports/:id', async (request, reply) => {
    const { id } = request.params;
    const report = repository.getReport(id);

    if (!report) {
      return reply.status(404).send({
        error: 'NOT_FOUND',
        message: `Report with ID "${id}" not found`,
      });
    }

    const reviewHistory = repository.getReviewsByReport(id);
    let dependenceGroup:
      | {
          groupId: string;
          reporterCount: number;
          effectiveWeight: number;
          commonFunderId?: string;
          faucetExempted: boolean;
        }
      | undefined = undefined;

    if (report.dependence_group_id) {
      const groupRecord = repository.getDependenceGroup(report.dependence_group_id);
      if (groupRecord) {
        dependenceGroup = {
          groupId: groupRecord.group_id,
          reporterCount: groupRecord.reporter_count,
          effectiveWeight: groupRecord.effective_weight,
          commonFunderId: groupRecord.common_funder_id ?? undefined,
          faucetExempted: Boolean(groupRecord.faucet_exempted),
        };
      }
    }

    const response: GetReportResponse = {
      report,
      review_history: reviewHistory,
      dependence_group: dependenceGroup,
    };

    GetReportResponseSchema.parse(response);
    return reply.status(200).send(response);
  });

  // 3. POST /v1/reports/:id/review - Review transition requiring reviewer auth
  fastify.post<{ Params: { id: string } }>('/v1/reports/:id/review', async (request, reply) => {
    const { id } = request.params;
    const reviewerContext = options.authenticateReviewer
      ? { ...options.authenticateReviewer(request), role: 'reviewer' as const, authenticated: true }
      : extractReviewerContext(request, options.reviewerAuth);

    if (!reviewerContext.authenticated) {
      return reply.status(403).send({
        error: 'FORBIDDEN',
        message:
          'Unauthorized: Active hard blocks and report reviews require authenticated human reviewer authority. Agent tokens are not permitted.',
      });
    }

    // Validate body schema
    const parseResult = ReviewReportRequestSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        error: 'INVALID_SCHEMA',
        message: 'Review request payload failed schema validation.',
        details: parseResult.error.issues,
      });
    }

    const existingReport = repository.getReport(id);
    if (!existingReport) {
      return reply.status(404).send({
        error: 'NOT_FOUND',
        message: `Report with ID "${id}" not found`,
      });
    }

    const now = getNow();
    try {
      const reviewResult = await lifecycleEngine.review(id, parseResult.data, reviewerContext, now);

      options.invalidateReceiver?.(existingReport.network as 'sandbox' | 'testnet', existingReport.accused_account_id, 'Report review changed authorization state');

      const response: ReviewReportResponse = {
        review_id: reviewResult.review.review_id,
        status: reviewResult.newStatus,
        blocklist_revision: reviewResult.blocklistRevision,
      };

      ReviewReportResponseSchema.parse(response);
      return reply.status(200).send(response);
    } catch (err: unknown) {
      const error = err as Error;
      if (error.name === 'InvalidStateTransitionError' || error.name === 'ReportExpiredError') {
        return reply.status(400).send({
          error: 'INVALID_TRANSITION',
          message: error.message,
        });
      }
      if (error.name === 'ReviewerAuthorizationError') {
        return reply.status(403).send({
          error: 'FORBIDDEN',
          message: error.message,
        });
      }
      throw err;
    }
  });

  // Revocation remains possible even when the originating report has expired or
  // become terminal. It uses the same independent reviewer and audit boundary.
  fastify.post<{ Params: { id: string } }>('/v1/blocklist/:id/revoke', async (request, reply) => {
    const reviewer = options.authenticateReviewer
      ? { ...options.authenticateReviewer(request), role: 'reviewer' as const, authenticated: true }
      : extractReviewerContext(request, options.reviewerAuth);
    if (!reviewer.authenticated) return reply.status(403).send({ error: 'FORBIDDEN', message: 'Configured reviewer authority is required' });
    const parsed = z.strictObject({ reason: z.string().trim().min(5).max(1000) }).safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: 'INVALID_SCHEMA', message: 'A bounded audit reason is required' });
    const entry = repository.getBlockById(request.params.id);
    if (!entry) return reply.status(404).send({ error: 'NOT_FOUND', message: 'Block entry was not found' });
    if (!entry.is_active) return reply.status(409).send({ error: 'ALREADY_REVOKED', message: 'Block entry is already inactive' });
    const result = await lifecycleEngine.revokeBlock(entry.entry_id, parsed.data.reason, reviewer, { now: getNow() });
    options.invalidateReceiver?.(entry.network as 'sandbox' | 'testnet', entry.accused_account_id, 'Reviewed block revocation changed authorization state');
    return { entry_id: entry.entry_id, blocklist_revision: result.revision, status: 'revoked' };
  });

  // 4. GET /v1/receivers/:network/:account/reports - Query receiver reports with discounted weights
  fastify.get<{ Params: { network: string; account: string } }>(
    '/v1/receivers/:network/:account/reports',
    async (request, reply) => {
      const { network, account } = request.params;

      if (!['testnet', 'mainnet', 'sandbox'].includes(network)) {
        return reply.status(400).send({
          error: 'INVALID_NETWORK',
          message: `Network "${network}" is not supported. Must be testnet, mainnet, or sandbox.`,
        });
      }

      const normalizedAccount = account.trim().toLowerCase();
      const now = getNow();

      // Active Blocklist Authority Invariant:
      // Raw report count alone NEVER triggers a block; only an active blocklist entry creates a hard block
      const activeBlock = repository.getActiveBlock(
        network as 'testnet' | 'mainnet' | 'sandbox',
        normalizedAccount,
      );

      const isBlocked = Boolean(
        activeBlock &&
          activeBlock.is_active === 1 &&
          (activeBlock.expires_at === null || activeBlock.expires_at > now),
      );

      const allReports = repository.getReportsByAccused(network, normalizedAccount);
      const validReports = allReports.filter((r) => r.expires_at > now);

      let graph: BoundedSubgraph | undefined;
      if (options.graphDataProvider) {
        graph = await traverseBoundedGraph(
          options.graphDataProvider,
          normalizedAccount,
          network as 'testnet' | 'mainnet' | 'sandbox',
          { asOfTimestamp: now },
        );
      }

      const resolvedLineages =
        typeof options.lineages === 'function'
          ? options.lineages(normalizedAccount)
          : options.lineages;

      // Compute Sybil clustering and discounted weights
      const clusteringResult = clusterDependenceGroups({
        network: network as 'testnet' | 'mainnet' | 'sandbox',
        reports: validReports.filter(report => ['submitted', 'references_verified', 'corroborated'].includes(report.status)),
        repository,
        faucetRegistry,
        graph,
        lineages: resolvedLineages,
        now,
      });

      const reportSummaries = validReports.map((r) => ({
        report_id: r.report_id,
        reporter_id: r.reporter_id,
        category: r.category,
        status: r.status,
        issued_at: r.issued_at,
        effective_weight: clusteringResult.reportWeightMap.get(r.report_id) ?? 0,
        dependence_group_id:
          clusteringResult.reporterGroupMap.get(r.reporter_id) ?? r.dependence_group_id ?? null,
      }));

      const response: ReceiverReportsResponse = {
        is_blocked: isBlocked,
        total_reports: validReports.length,
        effective_weight: clusteringResult.totalEffectiveWeight,
        reports: reportSummaries,
        dependence_groups: clusteringResult.dependenceGroups,
      };

      ReceiverReportsResponseSchema.parse(response);
      return reply.status(200).send(response);
    },
  );
};

/** Mount report routes in A's service using its database, auth and invalidation boundaries. */
export function createReportsPlugin(options: { now?: () => number; graphDataProvider?: GraphDataProvider } = {}) {
  return async (app: Parameters<FastifyPluginAsync>[0], context: ReportPluginContext): Promise<void> => {
    await app.register(reportsRoutes, { repository: new ReportRepository(context.store.database), now: options.now,
      authenticateReviewer: context.authenticateReviewer, invalidateReceiver: context.invalidateReceiver,
      graphDataProvider: options.graphDataProvider });
  };
}
