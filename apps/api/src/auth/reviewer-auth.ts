import { createHash, timingSafeEqual } from 'node:crypto';
import type { ReviewerContext } from '@counterparty-guard/reputation';
import type { FastifyReply, FastifyRequest } from 'fastify';
export interface ReviewerAuthConfig {
  reviewerTokens?: string[];
  defaultReviewerId?: string;
  credentials?: { token: string; reviewer_id: string; role: 'reviewer' | 'admin' }[];
}
const hash = (token: string) => createHash('sha256').update(token).digest();
/** Fixture route tests may inject credentials. Production uses A's separate reviewer authenticator. */
export function extractReviewerContext(request: FastifyRequest, config: ReviewerAuthConfig = {}): ReviewerContext {
  const header = request.headers.authorization;
  const custom = request.headers['x-reviewer-token'];
  const token = typeof custom === 'string' ? custom : typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7).trim() : '';
  const denied: ReviewerContext = { reviewer_id: 'unauthenticated', role: 'reviewer', authenticated: false };
  if (!token || token.length > 512) return denied;
  const credentials = config.credentials ?? (config.reviewerTokens ?? []).map(value => ({ token: value, reviewer_id: config.defaultReviewerId ?? 'configured-reviewer', role: 'reviewer' as const }));
  const credential = credentials.find(value => timingSafeEqual(hash(value.token), hash(token)));
  return credential ? { reviewer_id: credential.reviewer_id, role: credential.role, authenticated: true } : denied;
}
export async function requireReviewerAuth(request: FastifyRequest, reply: FastifyReply, config: ReviewerAuthConfig = {}): Promise<ReviewerContext> {
  const context = extractReviewerContext(request, config);
  if (!context.authenticated) {
    reply.status(403).send({ error: 'FORBIDDEN', message: 'Configured reviewer authority is required' });
    throw new Error('AUTH_FORBIDDEN');
  }
  return context;
}
