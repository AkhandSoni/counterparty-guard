export type Network = 'sandbox' | 'testnet' | 'mainnet';

export type Decision = 'allow' | 'warn' | 'block' | 'error';

export type ReasonCode =
  | 'ACTIVE_BLOCK'
  | 'REVIEWED_BLOCKLIST_MATCH'
  | 'CODE_CHANGED'
  | 'RECENT_DEPLOYMENT'
  | 'CIRCULAR_ACTIVITY'
  | 'DEPENDENT_REPORTS'
  | 'COMMON_FAUCET_EXEMPTED'
  | 'UNKNOWN_AGE'
  | 'INCOMPLETE_HISTORY'
  | 'MANDATORY_SOURCE_UNAVAILABLE'
  | 'POLICY_LIMIT_EXCEEDED';

export interface CheckActionParams {
  network: Network;
  vaultAccountId: string;
  receiverAccountId: string;
  actionKind: 'transfer_near' | 'contract_call';
  amountNear: string;
  methodName?: string;
  argsJson?: string;
}

export interface CheckActionVerdict {
  decision: Decision;
  riskScore: number; // 0–100 prototype indicator
  reasonCodes: ReasonCode[];
  freshness: string;
  sourceMode: 'fixture' | 'sandbox' | 'testnet';
  permit: {
    permitHash: string | null;
    nonce: string | null;
    policyRevision: number;
    expiresAt: number | null;
  } | null;
  timestamp: string;
}

export interface ScenarioDefinition {
  id: string; // S1 .. S10
  name: string;
  description: string;
  expectedDecision: Decision;
  params: CheckActionParams;
  verdict: CheckActionVerdict;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  type: 'creation' | 'deployment' | 'interaction' | 'report';
  title: string;
  description: string;
  txHash?: string;
  codeHash?: string;
  details?: Record<string, string | number | boolean>;
}

export interface DependenceGroup {
  groupId: string;
  commonFunder: string;
  memberReporters: string[];
  rawCount: number;
  effectiveWeight: number;
  discountFactor: number;
  discountReason: string;
  faucetExempted: boolean;
}

export interface CircularFlowInfo {
  detected: boolean;
  score: number;
  ringAccounts: string[];
  circularVolumePercent: number;
  discountPenalty: string;
  cyclePaths?: string[];
}

export interface GraphCoverage {
  accountsVisited: number;
  edgesTraversed: number;
  windowDays: number;
  truncated: boolean;
}

export type ReportCategory =
  | 'drainer'
  | 'phishing'
  | 'malicious_contract'
  | 'impersonation'
  | 'prompt_injection_source'
  | 'wash_trading'
  | 'other';

export type ReportStatus =
  | 'submitted'
  | 'references_verified'
  | 'corroborated'
  | 'reviewed'
  | 'dismissed'
  | 'rejected'
  | 'withdrawn'
  | 'expired';

export interface ReviewRecordMeta {
  reviewerId: string;
  decision: 'active_block' | 'dismissed' | 'corroborated' | 'rejected';
  scope: 'account' | 'code_hash' | 'both';
  reason: string;
  reviewedAt: number;
  blocklistRevision: number;
}

export interface ReportItem {
  id: string;
  accusedAccountId: string;
  reporterId: string;
  category: ReportCategory;
  description: string;
  status: ReportStatus;
  evidenceHashes: string[];
  txReferences: string[];
  issuedAt: number;
  dependenceGroupId?: string;
  effectiveWeight?: number;
  reviewRecord?: ReviewRecordMeta;
}

export interface PendingWarningContext {
  permitHash: string;
  vaultAccountId: string;
  receiverAccountId: string;
  amountNear: string;
  reasonCodes: string[];
}

export interface HistoricalObservations {
  firstSeenTimestamp: string;
  accountAgeDays: number;
  isContract: boolean;
  currentCodeHash: string | null;
  previousCodeHash?: string | null;
  codeHashChanged: boolean;
  deploymentTimestamp?: string | null;
  upgradeTimestamp?: string | null;
  lastInteractionTimestamp?: string | null;
  interactionCount: number;
  bytecodeSizeBytes?: number | null;
  upgradeReason?: string;
}

export interface FundingConnection {
  source: string;
  target: string;
  amountNear: string;
  timestamp: string;
  txHash: string;
  hopLevel: 1 | 2;
  isFaucet: boolean;
  description?: string;
}

export interface FaucetExemptionInfo {
  isExempted: boolean;
  faucetAccountId?: string;
  label?: string;
  exemptionType?: 'faucet' | 'bridge' | 'exchange' | 'system' | 'other';
  notes: string;
}

export interface ReceiverEvidenceData {
  accountId: string;
  network: Network;
  decision: Decision;
  riskScore: number;
  reasonCodes: ReasonCode[];
  isBlocked: boolean;
  blockReason?: string;
  blocklistRevision?: number;
  historical: HistoricalObservations;
  events: TimelineEvent[];
  reports: ReportItem[];
  coverage: GraphCoverage;
  fundingConnections: FundingConnection[];
  circularFlow: CircularFlowInfo;
  dependenceGroup?: DependenceGroup | null;
  faucetExemption: FaucetExemptionInfo;
}
