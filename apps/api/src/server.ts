import type { DatabaseSync } from 'node:sqlite';
import { ReportRepository, createDatabase, runMigrations } from '@counterparty-guard/reputation';
import cors from '@fastify/cors';
import Fastify, { type FastifyError, type FastifyInstance } from 'fastify';
import type { ReviewerAuthConfig } from './auth/reviewer-auth.js';
import { reportsRoutes } from './routes/reports.js';

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

  // Register CORS to enable frontend communication from apps/web
  await fastify.register(cors, {
    origin: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'x-reviewer-id',
      'x-reviewer-token',
      'x-csrf-token',
    ],
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

const isMain =
  process.argv[1] &&
  (process.argv[1].endsWith('server.ts') || process.argv[1].endsWith('server.js'));

if (isMain) {
  const port = Number(process.env.PORT || 3001);
  const host = process.env.HOST || '0.0.0.0';
  const server = await buildServer({ logger: true });
  try {
    await server.listen({ port, host });
    console.log(`API server listening on http://${host}:${port}`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}
