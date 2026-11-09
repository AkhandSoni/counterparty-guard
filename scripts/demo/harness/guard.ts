/**
 * @file scripts/demo/harness/guard.ts
 * @description In-process Counterparty Guard evaluation and interceptor wrapper for demo runners.
 */

import {
  type BoundedSubgraph,
  type DatabaseSync,
  ReportRepository,
  createDatabase,
  runMigrations,
} from '@counterparty-guard/reputation';
import type { Action, SignedPermit } from '@counterparty-guard/shared';
import type { Decision } from '@counterparty-guard/shared/demo';
import { assessFixtureAction } from './assessment.js';

/**
 * Thrown when Counterparty Guard halts execution before signing due to active blocklist match.
 */
export class CounterpartyBlockedError extends Error {
  public readonly receiverId: string;
  public readonly reasonCodes: string[];
  public readonly riskIndicator: number;

  constructor(receiverId: string, reasonCodes: string[], riskIndicator: number) {
    super(
      `CounterpartyBlocked: Transaction refused by Counterparty Guard before signing. Receiver "${receiverId}" is blocked (${reasonCodes.join(', ')}).`,
    );
    this.name = 'CounterpartyBlocked';
    this.receiverId = receiverId;
    this.reasonCodes = reasonCodes;
    this.riskIndicator = riskIndicator;
  }
}

/**
 * Thrown when Counterparty Guard pauses an action requiring human owner warning approval.
 */
export class WarningApprovalRequiredError extends Error {
  public readonly receiverId: string;
  public readonly permitHash: string;
  public readonly reasonCodes: string[];

  constructor(receiverId: string, permitHash: string, reasonCodes: string[]) {
    super(
      `WarningApprovalRequired: Action requires independent human owner approval on vault contract before signing. Permit hash: ${permitHash}`,
    );
    this.name = 'WarningApprovalRequired';
    this.receiverId = receiverId;
    this.permitHash = permitHash;
    this.reasonCodes = reasonCodes;
  }
}

export interface GuardEvaluationResult {
  decision: Decision;
  riskIndicator: number;
  reasonCodes: string[];
  reasons: string[];
  permit: SignedPermit | null;
  policyRevision: number;
  blocklistRevision: number;
}

/**
 * Initializes an in-memory SQLite database pre-seeded with S3 active blocklist entry.
 */
export function createDeterministicGuardDatabase(): {
  db: DatabaseSync;
  repository: ReportRepository;
} {
  const db = createDatabase({ path: ':memory:' });
  runMigrations(db);
  const repository = new ReportRepository(db);

  // Pre-seed Scenario S3: Known malicious drainer with reviewed active block
  repository.createActiveBlock({
    network: 'testnet',
    accused_account_id: 'known-drainer.testnet',
    scope: 'account',
    reason: 'Reviewed synthetic malicious fixture (S3); not a real allegation',
    reviewer_id: 'security_moderator_01',
  });

  return { db, repository };
}

/**
 * Evaluates counterparty reputation using in-process @counterparty-guard/reputation engine.
 */
export async function evaluateGuard(
  action: Action,
  repository: ReportRepository,
  network: 'testnet' | 'mainnet' | 'sandbox' = 'testnet',
  subgraph?: BoundedSubgraph,
  options?: {
    contractCodeHash?: string | null;
    priorApprovedCodeHash?: string | null;
  },
): Promise<GuardEvaluationResult> {
  const result = await assessFixtureAction(action, repository, { now: repository.now(), graph: subgraph, reportNetwork: network === 'sandbox' ? 'sandbox' : 'testnet',
    ageDays: action.receiver_id === 'merchant.testnet' ? 100 : null,
    independentCounterparties: action.receiver_id === 'merchant.testnet' ? 15 : 0,
    currentCode: options?.contractCodeHash, previousCode: options?.priorApprovedCodeHash });
  return { decision: result.decision, riskIndicator: result.risk_indicator, reasonCodes: result.reason_codes,
    reasons: result.reasons, permit: result.permit, policyRevision: Number(result.policy_revision), blocklistRevision: Number(result.blocklist_revision) };
}

export interface GuardedExecutionOutcome {
  decision: Decision;
  reasonCodes: string[];
  permitHash: string | null;
  signed: boolean;
  submitted: boolean;
  finalizedOutcome: string;
  receiverBalanceDelta: string;
}

/**
 * Executes agent payment tool under Counterparty Guard in-process protection.
 *
 * CRUCIAL SECURITY INVARIANT:
 * On decision: 'block', throws CounterpartyBlockedError BEFORE signing.
 * Guarantees signed: false, submitted: false, receiverBalanceDelta: '0'.
 */
export async function guardedAgentExecute(
  action: Action,
  repository: ReportRepository,
  network: 'testnet' | 'mainnet' | 'sandbox' = 'testnet',
  subgraph?: BoundedSubgraph,
  options?: {
    contractCodeHash?: string | null;
    priorApprovedCodeHash?: string | null;
  },
): Promise<GuardedExecutionOutcome> {
  // 1. Guard evaluates counterparty in-process BEFORE signing
  const evaluation = await evaluateGuard(action, repository, network, subgraph, options);

  // 2. Intercept blocked counterparties
  if (evaluation.decision === 'block') {
    throw new CounterpartyBlockedError(
      action.receiver_id,
      evaluation.reasonCodes,
      evaluation.riskIndicator,
    );
  }

  // 3. Intercept warning counterparties
  if (evaluation.decision === 'warn') {
    throw new WarningApprovalRequiredError(
      action.receiver_id,
      evaluation.permit?.permit_hash ?? '',
      evaluation.reasonCodes,
    );
  }

  // 4. Allowed transaction: proceed to simulated signing & submission
  const signed = false;
  const submitted = false;
  const delta = '0';

  return {
    decision: 'allow',
    reasonCodes: evaluation.reasonCodes,
    permitHash: evaluation.permit?.permit_hash ?? null,
    signed,
    submitted,
    finalizedOutcome: 'fixture_assessment_only',
    receiverBalanceDelta: delta,
  };
}
