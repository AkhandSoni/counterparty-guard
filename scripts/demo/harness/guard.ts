/**
 * @file scripts/demo/harness/guard.ts
 * @description In-process Counterparty Guard evaluation and interceptor wrapper for demo runners.
 */

import {
  type BoundedSubgraph,
  type DatabaseSync,
  ReportRepository,
  createDatabase,
  getReceiverReputation,
  runMigrations,
} from '@counterparty-guard/reputation';
import type { Action, Decision, ExecutionPermit } from '@counterparty-guard/shared';

function buildEstablishedSubgraph(seedAccountId: string, now = Date.now()): BoundedSubgraph {
  const normalizedSeed = seedAccountId.trim().toLowerCase();
  const nodes = new Map();
  nodes.set(normalizedSeed, { accountId: normalizedSeed, hop: 0, discoveredAt: now });
  for (let i = 1; i <= 15; i++) {
    const acc = `neighbor_${i}.testnet`;
    nodes.set(acc, { accountId: acc, hop: 1, discoveredAt: now });
  }
  const adjacency = new Map();
  for (const n of nodes.keys()) {
    adjacency.set(n, { inEdges: [], outEdges: [] });
  }
  return {
    seedAccountId: normalizedSeed,
    nodes,
    edges: [],
    adjacency,
    coverage: {
      accountsVisited: 16,
      edgesTraversed: 35,
      truncated: false,
      windowDays: 7,
    },
  };
}

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
  permit: ExecutionPermit | null;
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
    reason: 'Active blocklist entry: Confirmed wallet drainer contract (Scenario S3)',
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
  const targetReceiver = action.receiver_id;
  const effectiveSubgraph =
    subgraph ??
    (targetReceiver === 'merchant.testnet' ? buildEstablishedSubgraph(targetReceiver) : undefined);

  const reputation = await getReceiverReputation({
    network,
    accountId: targetReceiver,
    contractCodeHash: options?.contractCodeHash,
    priorApprovedCodeHash: options?.priorApprovedCodeHash,
    repository,
    subgraph: effectiveSubgraph,
  });

  const nowMs = Date.now();
  let decision: Decision = 'allow';
  let permit: ExecutionPermit | null = null;

  if (reputation.isBlocked) {
    decision = 'block';
  } else if (reputation.reputationRiskPoints >= 40) {
    decision = 'warn';
  } else {
    decision = 'allow';
  }

  if (decision !== 'block') {
    permit = {
      permit_hash: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e',
      encoded_permit_base64: 'eyJ2ZXJkaWN0IjoiYWxsb3ciLCJub25jZSI6Im5vbmNlXzAxIn0=',
      signature:
        'ed25519:HL9TyXQMqnAJNJZzA3kV8CA9ZFHtQsYfpJ6rq9b2Kt7sogU7zCp3iuwBisoAnerAtwZPqD1Uy79v1F6L3u6LP9W',
      verdict: decision === 'warn' ? 'warn' : 'allow',
      nonce: `nonce_${nowMs.toString(36)}`,
      issued_at: nowMs,
      expires_at: nowMs + 120_000,
    };
  }

  return {
    decision,
    riskIndicator: reputation.reputationRiskPoints,
    reasonCodes: reputation.reasonCodes,
    reasons: reputation.reasonCodes.map((c) => `Evaluated rule: ${c}`),
    permit,
    policyRevision: 1,
    blocklistRevision: reputation.blocklistRevision,
  };
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
  const signed = true;
  const submitted = true;
  const delta = action.kind === 'transfer_near' ? action.amount_yocto : '0';

  return {
    decision: 'allow',
    reasonCodes: evaluation.reasonCodes,
    permitHash: evaluation.permit?.permit_hash ?? null,
    signed,
    submitted,
    finalizedOutcome: 'executed_success',
    receiverBalanceDelta: delta,
  };
}
