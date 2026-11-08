import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { ZodError } from 'zod';
import { accountIdSchema, GuardError, networkSchema, type AgentRegistration } from '@counterparty-guard/shared';
import { authenticateAgent, authenticateReviewer } from './auth/credentials.js';
import { ApiError } from './errors.js';
import { AssessmentService, type AssessmentDependencies } from './services/assess.js';
import { digest, type GuardStore } from './storage/store.js';

export interface ReportPluginContext {
  store: GuardStore;
  authenticateAgent: (request: FastifyRequest) => AgentRegistration;
  authenticateReviewer: (request: FastifyRequest) => { reviewer_id: string };
  invalidateReceiver: GuardStore['invalidateReceiver'];
}
export interface AppOptions extends AssessmentDependencies {
  reviewerCredentialHash?: string;
  reportPlugin?: (app: FastifyInstance, context: ReportPluginContext) => void | Promise<void>;
  rateLimit?: { max: number; windowMs: number };
}

/** HTTP transport around A-owned services. C plugs in report routes without sharing agent authority. */
export function createApp(options: AppOptions): FastifyInstance {
  const app = Fastify({ logger: false, bodyLimit: 16_384, requestTimeout: 15_000, connectionTimeout: 10_000, trustProxy: false });
  const service = new AssessmentService(options);
  const now = options.clock ?? Date.now;
  const limit = options.rateLimit ?? { max: 120, windowMs: 60_000 };
  if (!Number.isInteger(limit.max) || limit.max < 1 || limit.max > 100_000 || !Number.isInteger(limit.windowMs) || limit.windowMs < 1 || limit.windowMs > 3_600_000) throw new Error('Invalid rate-limit configuration');
  const buckets = new Map<string, { count: number; until: number }>();
  const consume = (key: string): void => {
    const timestamp = now();
    if (buckets.size >= 10_000) {
      for (const [id, bucket] of buckets) if (bucket.until <= timestamp) buckets.delete(id);
      if (buckets.size >= 10_000 && !buckets.has(key)) throw new ApiError('RATE_LIMITED', 'Request capacity reached; retry later', 429);
    }
    const bucket = buckets.get(key);
    if (!bucket || bucket.until <= timestamp) { buckets.set(key, { count: 1, until: timestamp + limit.windowMs }); return; }
    if (++bucket.count > limit.max) throw new ApiError('RATE_LIMITED', 'Request limit exceeded; retry later', 429);
  };
  const agent = (request: FastifyRequest): AgentRegistration => {
    const registration = authenticateAgent(options.store, request);
    consume(`agent:${registration.agent_id}`);
    return registration;
  };
  app.addHook('onRequest', async request => {
    if (request.url.startsWith('/v1/')) consume(`ip:${request.ip}`);
  });
  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof ApiError || error instanceof GuardError) {
      return reply.code(error.statusCode).send({ error: { code: error.code, message: error.statusCode >= 500 ? 'Required authorization data is unavailable' : error.message }, permit: null });
    }
    const transportStatus = typeof error === 'object' && error !== null && 'statusCode' in error ? error.statusCode : undefined;
    if (error instanceof ZodError || transportStatus === 400 || transportStatus === 413) {
      return reply.code(transportStatus === 413 ? 413 : 400).send({ error: { code: 'INVALID_REQUEST', message: 'Request does not match the bounded API schema' }, permit: null });
    }
    return reply.code(503).send({ error: { code: 'EVIDENCE_UNAVAILABLE', message: 'Authorization could not be completed; retry the same request ID' }, permit: null });
  });
  app.get('/health', async (_request, reply) => {
    const healthy = options.store.isHealthy();
    return reply.code(healthy ? 200 : 503).send({ status: healthy ? 'ok' : 'unavailable', source_mode: options.sourceMode, database: healthy ? 'ready' : 'unavailable', execution_reconciliation: options.executionProvider ? 'configured' : 'not-configured', reports: options.reportPlugin ? 'configured' : 'not-configured', attestation: null });
  });
  app.post('/v1/checks', async request => service.assess(agent(request), request.body));
  app.get<{ Params: { id: string } }>('/v1/checks/:id', async request => {
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(request.params.id)) throw new ApiError('INVALID_REQUEST', 'Invalid check ID');
    return service.check(agent(request), request.params.id).response;
  });
  app.get<{ Params: { id: string } }>('/v1/checks/:id/evidence', async request => {
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(request.params.id)) throw new ApiError('INVALID_REQUEST', 'Invalid check ID');
    const stored = service.check(agent(request), request.params.id);
    return { check_id: stored.row.id, network: stored.row.network, source_mode: stored.row.source_mode,
      evidence_snapshot_hash: digest(stored.snapshot), snapshot: stored.snapshot, invalidated_reason: stored.row.invalidated_reason };
  });
  app.post<{ Params: { id: string } }>('/v1/checks/:id/revalidate', async request => {
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(request.params.id) || (request.body !== undefined && request.body !== null)) throw new ApiError('INVALID_REQUEST', 'Revalidation accepts only the original check ID');
    return service.revalidate(agent(request), request.params.id);
  });
  app.get<{ Params: { network: string; account: string } }>('/v1/receivers/:network/:account', async request => {
    const registration = agent(request);
    const network = networkSchema.parse(request.params.network);
    const account = accountIdSchema.parse(request.params.account);
    if (network !== registration.network) throw new ApiError('FORBIDDEN', 'Agent is not registered for this network', 403);
    const result = options.store.receiver(registration, account, options.sourceMode);
    if (!result) throw new ApiError('NOT_FOUND', 'No retained evidence for this receiver and agent', 404);
    return { network, source_mode: options.sourceMode, account_id: account, ...result };
  });
  app.get<{ Params: { id: string } }>('/v1/executions/:id', async request => {
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(request.params.id)) throw new ApiError('INVALID_REQUEST', 'Invalid execution ID');
    const result = await service.execution(agent(request), request.params.id);
    return result && { ...result, action: JSON.parse(result.action_json) as unknown, action_json: undefined, signed: Boolean(result.signed), submitted: Boolean(result.submitted), finalized: Boolean(result.finalized), nonexecution_proven: Boolean(result.nonexecution_proven) };
  });
  if (options.reportPlugin) {
    app.register(async instance => options.reportPlugin!(instance, {
      store: options.store,
      authenticateAgent: agent,
      authenticateReviewer: request => authenticateReviewer(options.reviewerCredentialHash, request, options.store),
      invalidateReceiver: options.store.invalidateReceiver.bind(options.store),
    }));
  }
  return app;
}
