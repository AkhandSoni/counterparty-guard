

export interface ReporterRecord {
  reporter_id: string;
  public_key: string;
  network: 'testnet' | 'mainnet' | 'sandbox';
  reputation_score: number;
  total_reports: number;
  created_at: number;
  updated_at: number;
}

export interface EvidenceReferenceRecord {
  evidence_id: string;
  report_id: string;
  reference_type: 'transaction' | 'receipt' | 'content_hash' | 'account';
  reference_value: string;
  verified: number;
  verified_at: number | null;
  verification_details: string | null;
  created_at: number;
}

export interface VerificationLogRecord {
  log_id: string;
  report_id: string;
  verifier_type: 'chain_rpc' | 'content_verifier' | 'automated_heuristics' | 'reviewer';
  check_name: string;
  passed: number;
  details: string | null;
  created_at: number;
}

export interface ActiveBlockRecord {
  entry_id: string;
  network: 'testnet' | 'mainnet' | 'sandbox';
  accused_account_id: string;
  contract_code_hash: string | null;
  scope: 'account' | 'code_hash' | 'both';
  reason: string;
  reviewer_id: string;
  report_id: string | null;
  is_active: number;
  created_at: number;
  expires_at: number | null;
  revoked_at: number | null;
  revoked_by: string | null;
  revocation_reason: string | null;
}

export interface BlocklistRevisionRecord {
  revision_number: number;
  entry_id: string;
  action: 'added' | 'updated' | 'revoked' | 'expired';
  network: 'testnet' | 'mainnet' | 'sandbox';
  accused_account_id: string;
  contract_code_hash: string | null;
  scope: 'account' | 'code_hash' | 'both';
  reviewer_id: string;
  reason: string;
  created_at: number;
}

export interface DependenceGroupRecord {
  group_id: string;
  network: 'testnet' | 'mainnet' | 'sandbox';
  common_funder_id: string | null;
  faucet_exempted: number;
  effective_weight: number;
  reporter_count: number;
  clustering_reason: string;
  created_at: number;
  updated_at: number;
}

export interface GroupMemberRecord {
  membership_id: string;
  group_id: string;
  account_id: string;
  role: 'reporter' | 'funder' | 'intermediary' | 'accused';
  hops_from_funder: number;
  observed_at: number;
}

export interface FaucetExemptionRecord {
  exemption_id: string;
  network: 'testnet' | 'mainnet' | 'sandbox';
  faucet_account_id: string;
  label: string;
  exemption_type: 'faucet' | 'bridge' | 'exchange' | 'system' | 'other';
  is_active: number;
  created_at: number;
  updated_at: number;
}

export interface CreateActiveBlockInput {
  network: 'testnet' | 'mainnet' | 'sandbox';
  accused_account_id: string;
  contract_code_hash?: string | null;
  scope: 'account' | 'code_hash' | 'both';
  reason: string;
  reviewer_id: string;
  report_id?: string | null;
  expires_at?: number | null;
}
