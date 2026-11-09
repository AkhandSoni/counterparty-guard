import type { DatabaseSync } from '@counterparty-guard/reputation';
import { ReportRepository, createDatabase, runMigrations } from '@counterparty-guard/reputation';
import Fastify, { type FastifyError, type FastifyInstance } from 'fastify';
import type { ReviewerAuthConfig } from '../src/auth/reviewer-auth.js';
import { reportsRoutes } from '../src/routes/reports.js';

import type { GraphDataProvider, ReporterFundingLineage } from '@counterparty-guard/reputation';

export interface ServerOptions {
  repository?: ReportRepository;
  db?: DatabaseSync;
  now?: () => number;
  reviewerAuth?: ReviewerAuthConfig;
  graphDataProvider?: GraphDataProvider;
  lineages?:
    | Map<string, ReporterFundingLineage>
    | ((account: string) => Map<string, ReporterFundingLineage>);
  logger?: boolean | object;
}

export async function buildServer(options: ServerOptions = {}): Promise<FastifyInstance> {
  const fastify = Fastify({
    logger: options.logger ?? false,
  });

  // Setup Database & Repository
  const db = options.db ?? createDatabase({ path: ':memory:' });
  if (!options.repository) {
    runMigrations(db);
  }
  const repository = options.repository ?? new ReportRepository(db);

  // Health check endpoint
  fastify.get('/health', async () => ({
    status: 'ok',
    timestamp: options.now ? options.now() : Date.now(),
  }));

  // Register Report Routes
  await fastify.register(reportsRoutes, {
    repository,
    now: options.now,
    reviewerAuth: options.reviewerAuth,
    graphDataProvider: options.graphDataProvider,
    lineages: options.lineages,
  });

  // Global error handler
  fastify.setErrorHandler((error: FastifyError, _request, reply) => {
    if (error.validation) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: error.message,
        details: error.validation,
      });
    }

    if (error.statusCode) {
      return reply.status(error.statusCode).send({
        error: error.name || 'HTTP_ERROR',
        message: error.message,
      });
    }

    fastify.log.error(error);
    return reply.status(500).send({
      error: 'INTERNAL_SERVER_ERROR',
      message: error.message || 'An unexpected server error occurred.',
    });
  });

  return fastify;
}
