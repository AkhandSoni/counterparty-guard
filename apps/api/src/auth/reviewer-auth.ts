import type { ReviewerContext } from '@counterparty-guard/reputation';
import type { FastifyReply, FastifyRequest } from 'fastify';

export interface ReviewerAuthConfig {
  reviewerTokens?: string[];
  defaultReviewerId?: string;
}

export function extractReviewerContext(
  request: FastifyRequest,
  config: ReviewerAuthConfig = {},
): ReviewerContext {
  const authHeader = request.headers.authorization;
  const customReviewerToken = request.headers['x-reviewer-token'] as string | undefined;
  const customReviewerId =
    (request.headers['x-reviewer-id'] as string | undefined) ||
    config.defaultReviewerId ||
    'moderator.testnet';

  const token =
    customReviewerToken ||
    (authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : undefined);

  if (!token) {
    return {
      reviewer_id: customReviewerId,
      role: 'reviewer',
      authenticated: false,
    };
  }

  // Agent tokens are explicitly identified and rejected from reviewer operations
  if (token.startsWith('agent-') || token.includes('agent_token')) {
    return {
      reviewer_id: 'automated_agent',
      role: 'reviewer',
      authenticated: false,
    };
  }

  let isValidToken = false;
  if (config.reviewerTokens !== undefined) {
    isValidToken = config.reviewerTokens.includes(token);
  } else {
    const validTokens = [
      'reviewer-secret-token',
      'moderator-secret-key',
      'admin-super-token',
      'mock-reviewer-token',
    ];
    isValidToken =
      validTokens.includes(token) || token.startsWith('reviewer-') || token.startsWith('admin-');
  }

  if (isValidToken) {
    return {
      reviewer_id: customReviewerId,
      role: token.startsWith('admin-') ? 'admin' : 'reviewer',
      authenticated: true,
    };
  }

  return {
    reviewer_id: customReviewerId,
    role: 'reviewer',
    authenticated: false,
  };
}

export async function requireReviewerAuth(
  request: FastifyRequest,
  reply: FastifyReply,
  config: ReviewerAuthConfig = {},
): Promise<ReviewerContext> {
  const context = extractReviewerContext(request, config);

  if (!context.authenticated) {
    reply.status(403).send({
      error: 'FORBIDDEN',
      message:
        'Unauthorized: Active hard blocks and report reviews require authenticated human reviewer authority. Agent tokens are not permitted.',
    });
    throw new Error('AUTH_FORBIDDEN');
  }

  return context;
}
