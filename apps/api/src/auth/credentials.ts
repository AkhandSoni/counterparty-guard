import { timingSafeEqual } from 'node:crypto';
import type { FastifyRequest } from 'fastify';
import type { AgentRegistration } from '@counterparty-guard/shared';
import { ApiError } from '../errors.js';
import { credentialHash, type GuardStore } from '../storage/store.js';

function bearer(request: FastifyRequest): string {
  const header = request.headers.authorization;
  const match = typeof header === 'string' ? /^Bearer ([A-Za-z0-9._~-]{16,512})$/.exec(header) : null;
  if (!match?.[1]) throw new ApiError('UNAUTHORIZED', 'A registered bearer credential is required', 401);
  return match[1];
}
export function authenticateAgent(store: GuardStore, request: FastifyRequest): AgentRegistration {
  const agent = store.authenticate(credentialHash(bearer(request)));
  if (!agent) throw new ApiError('UNAUTHORIZED', 'Invalid agent credential', 401);
  return agent;
}
export function authenticateReviewer(expectedHash: string | undefined, request: FastifyRequest, store: GuardStore): { reviewer_id: string } {
  const actual = credentialHash(bearer(request));
  if (store.authenticate(actual)) throw new ApiError('FORBIDDEN', 'Agent credentials cannot grant reviewer authority', 403);
  if (!expectedHash || !/^[0-9a-f]{64}$/.test(expectedHash) || !timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expectedHash, 'hex'))) throw new ApiError('FORBIDDEN', 'Reviewer authority is required', 403);
  return { reviewer_id: 'configured-reviewer' };
}
