export const errorCodes = ['INVALID_REQUEST', 'UNAUTHORIZED', 'FORBIDDEN', 'NOT_FOUND', 'POLICY_REJECTED', 'UNSUPPORTED_ACTION', 'SOURCE_UNAVAILABLE', 'SOURCE_STALE', 'EVIDENCE_UNAVAILABLE', 'REQUEST_CONFLICT', 'CHECK_EXPIRED', 'CHECK_INVALIDATED', 'ISSUANCE_IN_PROGRESS', 'INTERNAL_ERROR', 'RATE_LIMITED'] as const;
export type ErrorCode = typeof errorCodes[number];
export class GuardError extends Error {
  constructor(public readonly code: ErrorCode, message: string, public readonly statusCode = 400) { super(message); this.name = 'GuardError'; }
}
