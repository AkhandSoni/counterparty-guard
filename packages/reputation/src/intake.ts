import { randomUUID } from 'node:crypto';
import {
  REPORT_DOMAIN_SEPARATOR,
  type ReportRecord,
  type SubmitReportRequest,
  SubmitReportRequestSchema,
  type SubmitReportResponse,
  SubmitReportResponseSchema,
  verifyReportSignature,
} from '@counterparty-guard/shared';
import type { ReportIntakeStorage } from './storage/memory.js';
import type { ReportRepository } from './storage/repository.js';

export type IntakeErrorCode =
  | 'MALFORMED_JSON'
  | 'INVALID_SCHEMA'
  | 'EXPIRES_BEFORE_ISSUED'
  | 'REPORT_EXPIRED'
  | 'ISSUED_IN_FUTURE'
  | 'REPORTER_KEY_MISMATCH'
  | 'NONCE_REPLAY_DETECTED'
  | 'INVALID_SIGNATURE'
  | 'STORAGE_ERROR';

export interface IntakeErrorDetails {
  code: IntakeErrorCode;
  message: string;
  details?: Record<string, unknown> | unknown[];
  timestamp: number;
}

export class IntakeException extends Error {
  public readonly code: IntakeErrorCode;
  public readonly details?: Record<string, unknown> | unknown[];
  public readonly timestamp: number;
  public readonly httpStatus: number;

  constructor(
    code: IntakeErrorCode,
    message: string,
    details?: Record<string, unknown> | unknown[],
    timestamp = Date.now(),
  ) {
    super(message);
    this.name = 'IntakeException';
    this.code = code;
    this.details = details;
    this.timestamp = timestamp;
    this.httpStatus = getHttpStatusForIntakeErrorCode(code);
  }
}

export function getHttpStatusForIntakeErrorCode(code: IntakeErrorCode): number {
  switch (code) {
    case 'NONCE_REPLAY_DETECTED':
      return 409;
    case 'INVALID_SIGNATURE':
      return 401;
    case 'REPORTER_KEY_MISMATCH':
      return 403;
    case 'STORAGE_ERROR':
      return 500;
    default:
      return 400;
  }
}

export interface IntakeOptions {
  storage: ReportIntakeStorage | ReportRepository;
  now?: number; // Injected clock for deterministic testing (defaults to Date.now())
  clockSkewToleranceMs?: number; // Allowable future issuance tolerance (defaults to 300_000ms / 5min)
}

export type IntakeValidationResult =
  | {
      success: true;
      data: SubmitReportResponse;
      report: ReportRecord;
    }
  | {
      success: false;
      error: IntakeErrorDetails;
    };

/**
 * Validates and processes a signed report submission.
 * Returns a typed IntakeValidationResult envelope without throwing.
 */
export async function validateAndSubmitReport(
  rawInput: unknown,
  options: IntakeOptions,
): Promise<IntakeValidationResult> {
  const now = options.now ?? Date.now();
  const clockSkewToleranceMs = options.clockSkewToleranceMs ?? 300_000;

  // 1. JSON Parsing if string
  let parsedInput = rawInput;
  if (typeof rawInput === 'string') {
    try {
      parsedInput = JSON.parse(rawInput);
    } catch (err) {
      return {
        success: false,
        error: {
          code: 'MALFORMED_JSON',
          message: 'The submitted request body is not valid JSON.',
          details: { error: err instanceof Error ? err.message : String(err) },
          timestamp: now,
        },
      };
    }
  }

  // 2. Zod Schema Validation
  const parseResult = SubmitReportRequestSchema.safeParse(parsedInput);
  if (!parseResult.success) {
    const isExpiryOrderError = parseResult.error.issues.some(
      (issue) =>
        issue.path.includes('expires_at') &&
        issue.message.includes('strictly greater than issued_at'),
    );

    if (isExpiryOrderError) {
      return {
        success: false,
        error: {
          code: 'EXPIRES_BEFORE_ISSUED',
          message: 'Report expires_at must be strictly greater than issued_at.',
          details: parseResult.error.issues,
          timestamp: now,
        },
      };
    }

    return {
      success: false,
      error: {
        code: 'INVALID_SCHEMA',
        message: 'Report payload failed schema validation.',
        details: parseResult.error.issues,
        timestamp: now,
      },
    };
  }

  const payload: SubmitReportRequest = parseResult.data;

  // 3. Temporal & Expiry Invariants
  if (payload.expires_at <= payload.issued_at) {
    return {
      success: false,
      error: {
        code: 'EXPIRES_BEFORE_ISSUED',
        message: `Report expires_at (${payload.expires_at}) must be strictly greater than issued_at (${payload.issued_at}).`,
        details: { issued_at: payload.issued_at, expires_at: payload.expires_at },
        timestamp: now,
      },
    };
  }

  if (payload.expires_at <= now) {
    return {
      success: false,
      error: {
        code: 'REPORT_EXPIRED',
        message: `Report has already expired: expires_at (${payload.expires_at}) <= current_time (${now}).`,
        details: { expires_at: payload.expires_at, now },
        timestamp: now,
      },
    };
  }

  if (payload.issued_at > now + clockSkewToleranceMs) {
    return {
      success: false,
      error: {
        code: 'ISSUED_IN_FUTURE',
        message: `Report issued_at (${payload.issued_at}) is beyond clock skew tolerance (${clockSkewToleranceMs}ms ahead of current_time ${now}).`,
        details: { issued_at: payload.issued_at, now, clockSkewToleranceMs },
        timestamp: now,
      },
    };
  }

  // 4. Cryptographic Ed25519 Borsh Signature Verification
  let isSignatureValid = false;
  try {
    isSignatureValid = verifyReportSignature(payload);
  } catch (err) {
    return {
      success: false,
      error: {
        code: 'INVALID_SIGNATURE',
        message: `Signature verification failed due to internal error: ${err instanceof Error ? err.message : String(err)}`,
        timestamp: now,
      },
    };
  }

  if (!isSignatureValid) {
    return {
      success: false,
      error: {
        code: 'INVALID_SIGNATURE',
        message: `Cryptographic Ed25519 signature verification failed for payload under domain '${REPORT_DOMAIN_SEPARATOR}'.`,
        details: {
          reporter_id: payload.reporter_id,
          reporter_public_key: payload.reporter_public_key,
          domain: REPORT_DOMAIN_SEPARATOR,
        },
        timestamp: now,
      },
    };
  }

  // 5. Reporter Identity & Public Key Consistency
  try {
    const existingReporter = await options.storage.getReporter(payload.reporter_id);
    if (existingReporter) {
      if (existingReporter.public_key !== payload.reporter_public_key) {
        return {
          success: false,
          error: {
            code: 'REPORTER_KEY_MISMATCH',
            message: `Reporter '${payload.reporter_id}' is already registered with public key '${existingReporter.public_key}', but payload specified '${payload.reporter_public_key}'.`,
            details: {
              reporter_id: payload.reporter_id,
              registered_key: existingReporter.public_key,
              submitted_key: payload.reporter_public_key,
            },
            timestamp: now,
          },
        };
      }
    } else {
      await options.storage.registerReporter({
        reporter_id: payload.reporter_id,
        public_key: payload.reporter_public_key,
        network: payload.network,
        created_at: now,
      });
    }
  } catch (err) {
    return {
      success: false,
      error: {
        code: 'STORAGE_ERROR',
        message: `Failed to query or register reporter: ${err instanceof Error ? err.message : String(err)}`,
        timestamp: now,
      },
    };
  }

  // 6. Nonce Replay Protection
  try {
    const isUsed = await options.storage.hasNonce(payload.reporter_id, payload.nonce);
    if (isUsed) {
      return {
        success: false,
        error: {
          code: 'NONCE_REPLAY_DETECTED',
          message: `Nonce '${payload.nonce}' has already been used by reporter '${payload.reporter_id}'. Replay rejected.`,
          details: { reporter_id: payload.reporter_id, nonce: payload.nonce },
          timestamp: now,
        },
      };
    }
  } catch (err) {
    return {
      success: false,
      error: {
        code: 'STORAGE_ERROR',
        message: `Failed to check nonce uniqueness: ${err instanceof Error ? err.message : String(err)}`,
        timestamp: now,
      },
    };
  }

  // 7. Persist Record with status = "submitted"
  const reportId = randomUUID();
  const reportRecord: ReportRecord = {
    report_id: reportId,
    network: payload.network,
    accused_account_id: payload.accused_account_id,
    reporter_id: payload.reporter_id,
    reporter_public_key: payload.reporter_public_key,
    category: payload.category,
    description: payload.description,
    transaction_references: payload.transaction_references,
    evidence_content_hashes: payload.evidence_content_hashes,
    contract_code_hash: payload.contract_code_hash ?? null,
    status: 'submitted',
    issued_at: payload.issued_at,
    expires_at: payload.expires_at,
    nonce: payload.nonce,
    signature: payload.signature,
    dependence_group_id: null,
    created_at: now,
  };

  try {
    await options.storage.saveReport(reportRecord);
  } catch (err) {
    const isConstraint =
      err instanceof Error &&
      (err.message.includes('UNIQUE constraint') || err.message.includes('duplicate key'));

    if (isConstraint) {
      return {
        success: false,
        error: {
          code: 'NONCE_REPLAY_DETECTED',
          message: `Nonce '${payload.nonce}' has already been used by reporter '${payload.reporter_id}'. Replay rejected.`,
          details: { reporter_id: payload.reporter_id, nonce: payload.nonce },
          timestamp: now,
        },
      };
    }

    return {
      success: false,
      error: {
        code: 'STORAGE_ERROR',
        message: `Failed to persist report: ${err instanceof Error ? err.message : String(err)}`,
        timestamp: now,
      },
    };
  }

  // 8. Construct Response Envelope
  const responseData: SubmitReportResponse = {
    report_id: reportId,
    status: 'submitted',
    issued_at: payload.issued_at,
    expires_at: payload.expires_at,
  };

  SubmitReportResponseSchema.parse(responseData);

  return {
    success: true,
    data: responseData,
    report: reportRecord,
  };
}

/**
 * Throwing wrapper for caller ergonomics.
 */
export async function submitReport(
  rawInput: unknown,
  options: IntakeOptions,
): Promise<SubmitReportResponse> {
  const result = await validateAndSubmitReport(rawInput, options);
  if (!result.success) {
    throw new IntakeException(
      result.error.code,
      result.error.message,
      result.error.details,
      result.error.timestamp,
    );
  }
  return result.data;
}
