import {
  type Action,
  type CheckRequest,
  CheckRequestSchema,
  type CheckResponse,
  CheckResponseSchema,
  type Decision,
  type ExecutionPermit,
  ExecutionPermitSchema,
  type ReasonCode,
  type ScenarioId,
  ScenarioIdSchema,
} from '@counterparty-guard/shared';

export interface ActionParams {
  vaultAccountId: string;
  receiverAccountId: string;
  actionKind: 'transfer_near' | 'contract_call';
  amountNear: string;
  methodName?: string;
  argsJson?: string;
  network?: 'testnet' | 'mainnet' | 'sandbox';
}

export type ViewDecision = 'allow' | 'warn' | 'block' | 'error';

export interface ViewPermit {
  permitHash: string | null; // Raw canonical 64 hex characters (matching ExecutionPermitSchema)
  displayHash: string | null; // Formatted 0x-prefixed 66 characters for UI / CLI
  nonce: string | null;
  policyRevision: number;
  expiresAt: number | null;
}

export interface CheckActionVerdict {
  decision: ViewDecision;
  riskScore: number;
  reasonCodes: ReasonCode[];
  freshness: string;
  sourceMode: 'fixture' | 'sandbox' | 'testnet';
  permit: ViewPermit | null;
  timestamp: string;
}

export interface AdapterEvaluationResult {
  canonicalResponse: CheckResponse;
  verdict: CheckActionVerdict;
  params: ActionParams;
  permit: {
    canonical: ExecutionPermit | null;
    canonicalHash: string | null;
    displayHash: string | null;
    truncatedDisplayHash: string | null;
    nonce: string | null;
    policyRevision: number;
    expiresAt: number | null;
  } | null;
  matchedScenarioId: ScenarioId | 'CUSTOM';
  matchedScenarioName?: string;
  isCustomEvaluation: boolean;
  statusMessage?: string;
}

export interface ScenarioFixtureData {
  id: ScenarioId;
  name: string;
  description: string;
  expectedDecision: ViewDecision;
  params: ActionParams;
  riskScore: number;
  reasonCodes: ReasonCode[];
  reasons: string[];
  coverage: {
    accountsVisited: number;
    edgesTraversed: number;
    truncated: boolean;
    windowDays: number;
  };
  permitHash: string; // 64 hex characters
  nonce: string;
  policyRevision: number;
  blocklistRevision: number;
  freshness: string;
}

/**
 * Normalizes any permit hash format into canonical 64 lowercase hex characters.
 * Strips leading 0x/0X prefix, trims whitespace, verifies exactly 64 hex characters.
 */
export function normalizePermitHash(hash: string): string {
  if (!hash || typeof hash !== 'string') {
    throw new Error('Permit hash must be a non-empty string');
  }
  const clean = hash.trim().replace(/^0x/i, '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(clean)) {
    throw new Error(
      `Invalid permit hash: expected 64 hex characters, got "${hash}" (${clean.length} hex chars)`,
    );
  }
  return clean;
}

/**
 * Validates whether a string is a canonical 64-char lowercase hex permit hash.
 */
export function isCanonicalPermitHash(hash: string): boolean {
  return /^[a-f0-9]{64}$/.test(hash);
}

/**
 * Validates whether a string is an 0x-prefixed 64-hex permit hash (66 chars).
 */
export function is0xPermitHash(hash: string): boolean {
  return /^0x[a-f0-9]{64}$/i.test(hash);
}

/**
 * Formats a permit hash for UI display, command line strings, or truncated labels.
 */
export function formatDisplayPermitHash(
  hash: string | null | undefined,
  options?: {
    prefix0x?: boolean;
    truncate?: boolean;
    startChars?: number;
    endChars?: number;
  },
): string {
  if (!hash) return 'None';
  const prefix = options?.prefix0x !== false ? '0x' : '';
  const clean = hash.trim().replace(/^0x/i, '').toLowerCase();
  if (options?.truncate) {
    const start = options.startChars ?? 6;
    const end = options.endChars ?? 6;
    if (clean.length > start + end) {
      return `${prefix}${clean.slice(0, start)}...${clean.slice(-end)}`;
    }
  }
  return `${prefix}${clean}`;
}

/**
 * Converts a human-readable NEAR amount string (e.g. "0.05") to yoctoNEAR string (10^24)
 * using lossless BigInt string arithmetic.
 */
export function nearToYocto(nearAmount: string): string {
  const trimmed = nearAmount.trim();
  if (!/^\d+(\.\d+)?$/.test(trimmed)) {
    throw new Error(`Invalid NEAR amount format: "${nearAmount}"`);
  }
  const [whole = '0', fraction = ''] = trimmed.split('.');
  const paddedFraction = fraction.padEnd(24, '0').slice(0, 24);
  const yocto = BigInt(whole) * BigInt(10) ** BigInt(24) + BigInt(paddedFraction);
  return yocto.toString();
}

/**
 * Maps UI ActionParams to canonical Action schema from @counterparty-guard/shared.
 */
export function toCanonicalAction(params: ActionParams): Action {
  if (params.actionKind === 'contract_call') {
    const argsJson = params.argsJson?.trim() || '{}';
    let argsBase64 = '';
    try {
      if (typeof btoa !== 'undefined') {
        argsBase64 = btoa(argsJson);
      } else {
        argsBase64 = Buffer.from(argsJson, 'utf-8').toString('base64');
      }
    } catch {
      argsBase64 = Buffer.from('{}').toString('base64');
    }

    return {
      kind: 'contract_call',
      receiver_id: params.receiverAccountId,
      method_name: params.methodName || 'unknown_method',
      args_base64: argsBase64,
      attached_deposit_yocto: nearToYocto(params.amountNear || '0'),
      gas_tgas: 30,
    };
  }

  return {
    kind: 'transfer_near',
    receiver_id: params.receiverAccountId,
    amount_yocto: nearToYocto(params.amountNear || '0'),
  };
}

/**
 * Creates a valid canonical CheckRequest from ActionParams.
 */
export function toCanonicalCheckRequest(params: ActionParams, requestId?: string): CheckRequest {
  const req: CheckRequest = {
    schema_version: 1,
    network: params.network ?? 'testnet',
    vault_id: params.vaultAccountId,
    request_id: requestId ?? `req_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
    action: toCanonicalAction(params),
  };
  return CheckRequestSchema.parse(req);
}

/**
 * Generates a mock ExecutionPermit strictly conforming to ExecutionPermitSchema.
 */
function createMockExecutionPermit(
  rawPermitHash: string,
  verdict: 'allow' | 'warn',
  nonce: string,
  nowMs: number,
): ExecutionPermit {
  const canonicalHash = normalizePermitHash(rawPermitHash);
  // Deterministic 87-character base58 signature satisfying /^ed25519:[1-9A-HJ-NP-Za-km-z]{86,88}$/
  const dummySignature =
    'ed25519:HL9TyXQMqnAJNJZzA3kV8CA9ZFHtQsYfpJ6rq9b2Kt7sogU7zCp3iuwBisoAnerAtwZPqD1Uy79v1F6L3u6LP9W';

  let encodedBase64 = '';
  try {
    const payloadStr = JSON.stringify({ hash: canonicalHash, verdict, nonce });
    if (typeof btoa !== 'undefined') {
      encodedBase64 = btoa(payloadStr);
    } else {
      encodedBase64 = Buffer.from(payloadStr, 'utf-8').toString('base64');
    }
  } catch {
    encodedBase64 = 'eyJtb2NrIjp0cnVlfQ==';
  }

  const permit: ExecutionPermit = {
    permit_hash: canonicalHash,
    encoded_permit_base64: encodedBase64,
    signature: dummySignature,
    verdict,
    nonce,
    issued_at: nowMs,
    expires_at: nowMs + 15 * 60 * 1000,
  };
  return ExecutionPermitSchema.parse(permit);
}

/**
 * Canonical S1–S10 Fixture Dataset.
 */
export const SCENARIO_FIXTURES: Record<ScenarioId, ScenarioFixtureData> = {
  S1: {
    id: 'S1',
    name: 'Established Legitimate Receiver',
    description:
      'Receiver has 6+ months active history, independent funding, and clean transaction record.',
    expectedDecision: 'allow',
    params: {
      network: 'testnet',
      vaultAccountId: 'vault.agent-c.testnet',
      receiverAccountId: 'merchant.testnet',
      actionKind: 'transfer_near',
      amountNear: '0.05',
    },
    riskScore: 5,
    reasonCodes: [],
    reasons: ['Receiver has verified clean transaction history and established activity.'],
    coverage: {
      accountsVisited: 18,
      edgesTraversed: 45,
      truncated: false,
      windowDays: 7,
    },
    permitHash: '7a8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
    nonce: 'nonce_s1_78a9c0',
    policyRevision: 7,
    blocklistRevision: 7,
    freshness: '12s ago (Block #142890120)',
  },
  S2: {
    id: 'S2',
    name: 'Legitimate New Receiver',
    description:
      'Account created < 24h ago with zero history. Requires explicit owner warning approval.',
    expectedDecision: 'warn',
    params: {
      network: 'testnet',
      vaultAccountId: 'vault.agent-c.testnet',
      receiverAccountId: 'new-vendor.testnet',
      actionKind: 'transfer_near',
      amountNear: '0.05',
    },
    riskScore: 45,
    reasonCodes: ['RECENT_DEPLOYMENT', 'UNKNOWN_AGE'],
    reasons: ['Account created < 24h ago; requires independent human owner warning approval.'],
    coverage: {
      accountsVisited: 4,
      edgesTraversed: 3,
      truncated: false,
      windowDays: 7,
    },
    permitHash: '9b8e21a0f54318c39e2d765418b7654321908765432109876543210987654321',
    nonce: 'nonce_s2_12b3c4',
    policyRevision: 7,
    blocklistRevision: 7,
    freshness: '5s ago (Block #142890128)',
  },
  S3: {
    id: 'S3',
    name: 'Reviewed Malicious Receiver',
    description:
      'Receiver has active reviewed blocklist entry for confirmed drainer activity. Refused before signing.',
    expectedDecision: 'block',
    params: {
      network: 'testnet',
      vaultAccountId: 'vault.agent-c.testnet',
      receiverAccountId: 'known-drainer.testnet',
      actionKind: 'transfer_near',
      amountNear: '0.05',
    },
    riskScore: 100,
    reasonCodes: ['ACTIVE_BLOCK', 'REVIEWED_BLOCKLIST_MATCH'],
    reasons: [
      'Explicit active blocklist match confirmed by human moderator. Signing refused before dispatch.',
    ],
    coverage: {
      accountsVisited: 8,
      edgesTraversed: 14,
      truncated: false,
      windowDays: 7,
    },
    permitHash: '',
    nonce: '',
    policyRevision: 7,
    blocklistRevision: 7,
    freshness: '1s ago (Block #142890130)',
  },
  S4: {
    id: 'S4',
    name: 'False-Report Flood Attack',
    description:
      '20 Sybil accounts sharing common funder submit duplicate allegations. Group weight capped to 1.0; no hard block.',
    expectedDecision: 'allow',
    params: {
      network: 'testnet',
      vaultAccountId: 'vault.agent-c.testnet',
      receiverAccountId: 'popular-service.testnet',
      actionKind: 'transfer_near',
      amountNear: '0.05',
    },
    riskScore: 20,
    reasonCodes: ['DEPENDENT_REPORTS'],
    reasons: [
      '20 correlated allegations clustered to single dependence group; effective weight capped to 1.0.',
    ],
    coverage: {
      accountsVisited: 32,
      edgesTraversed: 84,
      truncated: false,
      windowDays: 7,
    },
    permitHash: '3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d',
    nonce: 'nonce_s4_99x87z',
    policyRevision: 7,
    blocklistRevision: 7,
    freshness: '45s ago (Block #142890080)',
  },
  S5: {
    id: 'S5',
    name: 'Circular Activity Manipulation',
    description:
      'Receiver manufactures fake transaction volume in closed 3-account ring. Volume discounted with warning.',
    expectedDecision: 'warn',
    params: {
      network: 'testnet',
      vaultAccountId: 'vault.agent-c.testnet',
      receiverAccountId: 'wash-trader.testnet',
      actionKind: 'transfer_near',
      amountNear: '0.05',
    },
    riskScore: 65,
    reasonCodes: ['CIRCULAR_ACTIVITY'],
    reasons: [
      'Reciprocal money flows detected in closed 3-account ring; transaction credit penalized.',
    ],
    coverage: {
      accountsVisited: 12,
      edgesTraversed: 28,
      truncated: false,
      windowDays: 7,
    },
    permitHash: '5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f',
    nonce: 'nonce_s5_circle8',
    policyRevision: 7,
    blocklistRevision: 7,
    freshness: '20s ago (Block #142890105)',
  },
  S6: {
    id: 'S6',
    name: 'Shared Common Faucet Control',
    description:
      'Accounts sharing testnet faucet funder are exempted from sybil clustering penalties.',
    expectedDecision: 'allow',
    params: {
      network: 'testnet',
      vaultAccountId: 'vault.agent-c.testnet',
      receiverAccountId: 'user-b.testnet',
      actionKind: 'transfer_near',
      amountNear: '0.05',
    },
    riskScore: 10,
    reasonCodes: ['COMMON_FAUCET_EXEMPTED'],
    reasons: ['Common testnet faucet funding exempted from Sybil clustering penalty.'],
    coverage: {
      accountsVisited: 15,
      edgesTraversed: 22,
      truncated: false,
      windowDays: 7,
    },
    permitHash: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
    nonce: 'nonce_s6_faucet0',
    policyRevision: 7,
    blocklistRevision: 7,
    freshness: '10s ago (Block #142890115)',
  },
  S7: {
    id: 'S7',
    name: 'Upgraded Contract Receiver',
    description:
      'Trusted contract deployed new bytecode. Forces warning reassessment despite historical trust.',
    expectedDecision: 'warn',
    params: {
      network: 'testnet',
      vaultAccountId: 'vault.agent-c.testnet',
      receiverAccountId: 'contract.testnet',
      actionKind: 'contract_call',
      amountNear: '0.05',
      methodName: 'claim_reward',
      argsJson: '{"id": 101}',
    },
    riskScore: 55,
    reasonCodes: ['CODE_CHANGED'],
    reasons: ['Contract bytecode hash updated since prior interaction; requires re-approval.'],
    coverage: {
      accountsVisited: 10,
      edgesTraversed: 16,
      truncated: false,
      windowDays: 7,
    },
    permitHash: '7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e',
    nonce: 'nonce_s7_upgraded',
    policyRevision: 7,
    blocklistRevision: 7,
    freshness: '3s ago (Block #142890129)',
  },
  S8: {
    id: 'S8',
    name: 'Permit Replay / Mutation',
    description: 'Mutated permit parameters or replayed nonce rejected on-chain by vault contract.',
    expectedDecision: 'error',
    params: {
      network: 'testnet',
      vaultAccountId: 'vault.agent-c.testnet',
      receiverAccountId: 'merchant.testnet',
      actionKind: 'transfer_near',
      amountNear: '5.0',
    },
    riskScore: 90,
    reasonCodes: ['POLICY_LIMIT_EXCEEDED'],
    reasons: ['Mutated permit parameters rejected; amount exceeds max single transfer allowance.'],
    coverage: {
      accountsVisited: 5,
      edgesTraversed: 8,
      truncated: false,
      windowDays: 7,
    },
    permitHash: '',
    nonce: '',
    policyRevision: 7,
    blocklistRevision: 7,
    freshness: 'Now (Rejected on-chain)',
  },
  S9: {
    id: 'S9',
    name: 'Provider Outage',
    description:
      'Mandatory NEAR RPC provider unreachable. Fails closed with typed 503 error; no permit created.',
    expectedDecision: 'error',
    params: {
      network: 'testnet',
      vaultAccountId: 'vault.agent-c.testnet',
      receiverAccountId: 'unknown-target.testnet',
      actionKind: 'transfer_near',
      amountNear: '0.05',
    },
    riskScore: 0,
    reasonCodes: ['INCOMPLETE_HISTORY', 'MANDATORY_SOURCE_UNAVAILABLE'],
    reasons: [
      'Mandatory NEAR RPC provider timed out after 60s; fails closed safely without permit.',
    ],
    coverage: {
      accountsVisited: 0,
      edgesTraversed: 0,
      truncated: false,
      windowDays: 7,
    },
    permitHash: '',
    nonce: '',
    policyRevision: 7,
    blocklistRevision: 7,
    freshness: 'Timeout after 60s',
  },
  S10: {
    id: 'S10',
    name: 'Supported Method Call',
    description:
      'Contract call targeting explicitly configured and allowlisted method succeeds cleanly.',
    expectedDecision: 'allow',
    params: {
      network: 'testnet',
      vaultAccountId: 'vault.agent-c.testnet',
      receiverAccountId: 'fixture.testnet',
      actionKind: 'contract_call',
      amountNear: '0.01',
      methodName: 'claim_service',
      argsJson: '{"id": 42}',
    },
    riskScore: 5,
    reasonCodes: [],
    reasons: ['Contract call targets allowlisted method claim_service with valid parameters.'],
    coverage: {
      accountsVisited: 6,
      edgesTraversed: 11,
      truncated: false,
      windowDays: 7,
    },
    permitHash: '4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b',
    nonce: 'nonce_s10_method_ok',
    policyRevision: 7,
    blocklistRevision: 7,
    freshness: '15s ago (Block #142890110)',
  },
};

/**
 * Standalone FixtureMockAdapter class.
 */
export class FixtureMockAdapter {
  private scenarios: Record<ScenarioId, ScenarioFixtureData>;

  constructor(customScenarios?: Record<ScenarioId, ScenarioFixtureData>) {
    this.scenarios = customScenarios ?? { ...SCENARIO_FIXTURES };
  }

  /**
   * Evaluates an explicit scenario by its ID (S1 through S10).
   */
  public evaluateScenario(scenarioId: ScenarioId): AdapterEvaluationResult {
    const validId = ScenarioIdSchema.parse(scenarioId);
    const fixture = this.scenarios[validId];
    if (!fixture) {
      throw new Error(`Scenario with ID "${scenarioId}" not found in mock fixtures.`);
    }
    return this.buildResultFromFixture(fixture, fixture.params);
  }

  /**
   * Resolves arbitrary or user-modified ActionParams against S1–S10 scenario datasets.
   * If an exact scenario match is found, returns that fixture.
   * Otherwise, applies intelligent defensive heuristics.
   */
  public evaluate(
    params: ActionParams,
    options?: { forceScenarioId?: ScenarioId },
  ): AdapterEvaluationResult {
    if (options?.forceScenarioId) {
      return this.evaluateScenario(options.forceScenarioId);
    }

    // 1. Check for exact scenario match by receiver and action
    const matchedId = this.findMatchingScenarioId(params);
    if (matchedId) {
      const fixture = this.scenarios[matchedId];
      return this.buildResultFromFixture(fixture, params);
    }

    // 2. Dynamic heuristic evaluation for custom inputs
    return this.evaluateCustomAction(params);
  }

  /**
   * Lists all available scenario definitions.
   */
  public listScenarios(): ScenarioFixtureData[] {
    return Object.values(this.scenarios);
  }

  /**
   * Gets a specific scenario fixture.
   */
  public getScenario(scenarioId: ScenarioId): ScenarioFixtureData | undefined {
    return this.scenarios[scenarioId];
  }

  /**
   * Builds the comprehensive evaluation result, ensuring canonical CheckResponse compliance.
   */
  private buildResultFromFixture(
    fixture: ScenarioFixtureData,
    params: ActionParams,
  ): AdapterEvaluationResult {
    const nowMs = Date.now();
    const isBlockOrError =
      fixture.expectedDecision === 'block' || fixture.expectedDecision === 'error';

    let canonicalPermit: ExecutionPermit | null = null;
    let canonicalHash: string | null = null;
    let displayHash: string | null = null;
    let truncatedDisplayHash: string | null = null;

    if (!isBlockOrError && fixture.permitHash) {
      canonicalHash = normalizePermitHash(fixture.permitHash);
      displayHash = formatDisplayPermitHash(canonicalHash);
      truncatedDisplayHash = formatDisplayPermitHash(canonicalHash, { truncate: true });
      canonicalPermit = createMockExecutionPermit(
        canonicalHash,
        fixture.expectedDecision === 'warn' ? 'warn' : 'allow',
        fixture.nonce,
        nowMs,
      );
    }

    // Canonical decision in CheckResponse must be 'allow' | 'warn' | 'block'
    const canonicalDecision: Decision =
      fixture.expectedDecision === 'error' ? 'block' : fixture.expectedDecision;

    const scenarioNum = Number.parseInt(fixture.id.replace('S', ''), 10);
    const hexSuffix = Number.isNaN(scenarioNum)
      ? '000000000001'
      : scenarioNum.toString(16).padStart(12, '0');
    const canonicalResponse: CheckResponse = {
      check_id: `00000000-0000-4000-8000-${hexSuffix}`,
      schema_version: 1,
      agent_id: 'agent-c.testnet',
      decision: canonicalDecision,
      risk_indicator: fixture.riskScore,
      reason_codes: fixture.reasonCodes,
      reasons: fixture.reasons,
      evidence_refs: [],
      coverage: {
        accounts_visited: fixture.coverage.accountsVisited,
        edges_traversed: fixture.coverage.edgesTraversed,
        truncated: fixture.coverage.truncated,
        window_days: fixture.coverage.windowDays,
      },
      source_mode: 'fixture',
      evaluated_at: nowMs,
      expires_at: nowMs + 15 * 60 * 1000,
      policy_revision: fixture.policyRevision,
      blocklist_revision: fixture.blocklistRevision,
      permit: canonicalPermit,
      attestation: null,
    };

    // Strictly validate against shared schema
    CheckResponseSchema.parse(canonicalResponse);

    const verdict: CheckActionVerdict = {
      decision: fixture.expectedDecision,
      riskScore: fixture.riskScore,
      reasonCodes: fixture.reasonCodes,
      freshness: fixture.freshness,
      sourceMode: 'fixture',
      permit: canonicalPermit
        ? {
            permitHash: canonicalHash,
            displayHash: displayHash,
            nonce: canonicalPermit.nonce,
            policyRevision: fixture.policyRevision,
            expiresAt: canonicalPermit.expires_at,
          }
        : null,
      timestamp: new Date().toISOString(),
    };

    return {
      canonicalResponse,
      verdict,
      params,
      permit: canonicalPermit
        ? {
            canonical: canonicalPermit,
            canonicalHash,
            displayHash,
            truncatedDisplayHash,
            nonce: canonicalPermit.nonce,
            policyRevision: fixture.policyRevision,
            expiresAt: canonicalPermit.expires_at,
          }
        : null,
      matchedScenarioId: fixture.id,
      matchedScenarioName: fixture.name,
      isCustomEvaluation: false,
    };
  }

  /**
   * Matches params to one of S1–S10 based on receiverAccountId and action characteristics.
   */
  private findMatchingScenarioId(params: ActionParams): ScenarioId | null {
    const receiver = params.receiverAccountId.trim().toLowerCase();
    const amount = Number.parseFloat(params.amountNear || '0');

    if (receiver === 'merchant.testnet') {
      return amount >= 5.0 ? 'S8' : 'S1';
    }
    if (receiver === 'new-vendor.testnet') return 'S2';
    if (receiver === 'known-drainer.testnet') return 'S3';
    if (receiver === 'popular-service.testnet') return 'S4';
    if (receiver === 'wash-trader.testnet') return 'S5';
    if (receiver === 'user-b.testnet') return 'S6';
    if (receiver === 'contract.testnet') return 'S7';
    if (receiver === 'unknown-target.testnet') return 'S9';
    if (receiver === 'fixture.testnet') return 'S10';

    return null;
  }

  /**
   * Dynamic risk evaluation for user-entered custom parameters.
   */
  private evaluateCustomAction(params: ActionParams): AdapterEvaluationResult {
    const nowMs = Date.now();
    const receiver = params.receiverAccountId.trim().toLowerCase();
    const amount = Number.parseFloat(params.amountNear || '0');

    let decision: ViewDecision = 'allow';
    let riskScore = 15;
    const reasonCodes: ReasonCode[] = [];
    const reasons: string[] = [];

    // Rule 1: Malicious keyword detection
    if (
      receiver.includes('drain') ||
      receiver.includes('malicious') ||
      receiver.includes('phish') ||
      receiver.includes('exploit') ||
      receiver.includes('scam')
    ) {
      decision = 'block';
      riskScore = 100;
      reasonCodes.push('ACTIVE_BLOCK', 'REVIEWED_BLOCKLIST_MATCH');
      reasons.push('Counterparty matched high-risk adversarial indicator in blocklist database.');
    }
    // Rule 2: Large value transfer policy limit
    else if (amount > 10.0) {
      decision = 'warn';
      riskScore = 80;
      reasonCodes.push('POLICY_LIMIT_EXCEEDED');
      reasons.push(
        'Requested amount exceeds autonomous threshold (> 10 NEAR). Requires owner warning approval.',
      );
    }
    // Rule 3: Contract call evaluation
    else if (params.actionKind === 'contract_call') {
      const method = (params.methodName || '').trim().toLowerCase();
      if (['transfer', 'set_owner', 'upgrade', 'execute'].includes(method)) {
        decision = 'warn';
        riskScore = 70;
        reasonCodes.push('CODE_CHANGED', 'UNKNOWN_AGE');
        reasons.push(`Sensitive method call "${method}" requires owner warning approval.`);
      } else {
        decision = 'allow';
        riskScore = 20;
        reasons.push(`Standard contract call to "${method}" approved.`);
      }
    }
    // Rule 4: Unknown account warning
    else if (receiver.endsWith('.testnet') || receiver.endsWith('.near')) {
      decision = 'warn';
      riskScore = 40;
      reasonCodes.push('UNKNOWN_AGE');
      reasons.push('Unverified account age. Requires owner warning approval.');
    }

    const isBlock = decision === 'block';
    let canonicalPermit: ExecutionPermit | null = null;
    let canonicalHash: string | null = null;
    let displayHash: string | null = null;
    let truncatedDisplayHash: string | null = null;

    if (!isBlock) {
      // Deterministic hash based on receiver and amount
      const rawHex = 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e';
      canonicalHash = rawHex;
      displayHash = formatDisplayPermitHash(canonicalHash);
      truncatedDisplayHash = formatDisplayPermitHash(canonicalHash, { truncate: true });
      canonicalPermit = createMockExecutionPermit(
        canonicalHash,
        decision === 'warn' ? 'warn' : 'allow',
        `nonce_custom_${nowMs.toString(36)}`,
        nowMs,
      );
    }

    const canonicalDecision: Decision =
      (decision as string) === 'error' ? 'block' : (decision as Decision);

    const canonicalResponse: CheckResponse = {
      check_id: `00000000-0000-4000-9000-${Math.random().toString(16).substring(2, 14).padEnd(12, '0')}`,
      schema_version: 1,
      agent_id: 'agent-c.testnet',
      decision: canonicalDecision,
      risk_indicator: riskScore,
      reason_codes: reasonCodes,
      reasons: reasons.length > 0 ? reasons : ['Dynamic heuristic evaluation completed.'],
      evidence_refs: [],
      coverage: {
        accounts_visited: 5,
        edges_traversed: 10,
        truncated: false,
        window_days: 7,
      },
      source_mode: 'fixture',
      evaluated_at: nowMs,
      expires_at: nowMs + 15 * 60 * 1000,
      policy_revision: 7,
      blocklist_revision: 7,
      permit: canonicalPermit,
      attestation: null,
    };

    CheckResponseSchema.parse(canonicalResponse);

    const verdict: CheckActionVerdict = {
      decision,
      riskScore,
      reasonCodes,
      freshness: 'Just evaluated (Dynamic Mock)',
      sourceMode: 'fixture',
      permit: canonicalPermit
        ? {
            permitHash: canonicalHash,
            displayHash,
            nonce: canonicalPermit.nonce,
            policyRevision: 7,
            expiresAt: canonicalPermit.expires_at,
          }
        : null,
      timestamp: new Date().toISOString(),
    };

    return {
      canonicalResponse,
      verdict,
      params,
      permit: canonicalPermit
        ? {
            canonical: canonicalPermit,
            canonicalHash,
            displayHash,
            truncatedDisplayHash,
            nonce: canonicalPermit.nonce,
            policyRevision: 7,
            expiresAt: canonicalPermit.expires_at,
          }
        : null,
      matchedScenarioId: 'CUSTOM',
      matchedScenarioName: 'Custom Parameter Evaluation',
      isCustomEvaluation: true,
      statusMessage: 'Dynamic heuristic evaluation applied.',
    };
  }
}

/**
 * Singleton instance of FixtureMockAdapter.
 */
export const mockAdapter = new FixtureMockAdapter();

/**
 * Convenience functional exports for direct invocation.
 */
export function evaluateAction(
  params: ActionParams,
  options?: { forceScenarioId?: ScenarioId },
): AdapterEvaluationResult {
  return mockAdapter.evaluate(params, options);
}

export function evaluateScenario(scenarioId: ScenarioId): AdapterEvaluationResult {
  return mockAdapter.evaluateScenario(scenarioId);
}
