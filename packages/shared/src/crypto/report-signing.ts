import * as borsh from 'borsh';
import type { SubmitReportRequest } from '../schemas/report.js';
import { signDetached, verifyDetached } from './ed25519.js';

export const REPORT_DOMAIN_SEPARATOR = 'COUNTERPARTY_GUARD_REPORT_V1';

export const BorshReportPayloadSchema = {
  struct: {
    domain: 'string',
    network: 'string',
    accused_account_id: 'string',
    reporter_id: 'string',
    reporter_public_key: 'string',
    category: 'string',
    description: 'string',
    transaction_references: { array: { type: 'string' } },
    evidence_content_hashes: { array: { type: 'string' } },
    contract_code_hash: { option: 'string' },
    issued_at: 'u64',
    expires_at: 'u64',
    nonce: 'string',
  },
};

export type ReportSignablePayload = Omit<SubmitReportRequest, 'signature'>;

export function serializeReportForSigning(
  payload: ReportSignablePayload,
  domain = REPORT_DOMAIN_SEPARATOR,
): Uint8Array {
  const normalized = {
    domain,
    network: payload.network,
    accused_account_id: payload.accused_account_id,
    reporter_id: payload.reporter_id,
    reporter_public_key: payload.reporter_public_key,
    category: payload.category,
    description: payload.description,
    transaction_references: payload.transaction_references || [],
    evidence_content_hashes: payload.evidence_content_hashes || [],
    contract_code_hash: payload.contract_code_hash || null,
    issued_at: BigInt(payload.issued_at),
    expires_at: BigInt(payload.expires_at),
    nonce: payload.nonce,
  };
  return borsh.serialize(BorshReportPayloadSchema, normalized);
}

export function signReportPayload(payload: ReportSignablePayload, secretKey: Uint8Array): string {
  const serialized = serializeReportForSigning(payload);
  return signDetached(serialized, secretKey);
}

export function verifyReportSignature(report: SubmitReportRequest): boolean {
  if (report.expires_at <= report.issued_at) {
    return false;
  }
  const serialized = serializeReportForSigning(report);
  return verifyDetached(serialized, report.signature, report.reporter_public_key);
}
