import Database from 'better-sqlite3';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  agentRegistrationSchema, checkResponseSchema, executionObservationSchema, canonicalJson, decodePublicKey,
  type AgentRegistration, type CheckRequest, type CheckResponse, type ExecutionObservation,
  type Network, type PolicySnapshot, type ReceiverEvidence, type ReputationSnapshot, type SourceMode,
} from '@counterparty-guard/shared';
import { ApiError } from '../errors.js';
import { migrate } from './migrate.js';

export const canonical = canonicalJson;
export const digest = (value: unknown): string => createHash('sha256').update(canonical(value)).digest('hex');
export const credentialHash = (credential: string): string => createHash('sha256').update(credential).digest('hex');

export interface EvidenceSnapshot {
  evidence: ReceiverEvidence;
  reputation: ReputationSnapshot;
  policy: PolicySnapshot;
  history: { finalized_successes: number; approved_code_identity: string | null };
}
interface CheckRow {
  id: string; agent_id: string; request_id: string; network: Network; vault_id: string; source_mode: SourceMode;
  action_json: string; fingerprint: string; nonce: string; state: string; lease_owner: string | null;
  lease_until: number; response_json: string | null; snapshot_id: string | null; expires_at: number | null;
  invalidated_reason: string | null; created_at: number;
}
export interface Claim {
  id: string; nonce: string; owner: string; cached: CheckResponse | null;
}
export interface StoredCheck { row: CheckRow; response: CheckResponse; snapshot: EvidenceSnapshot }
export interface ExecutionRecord {
  id: string; check_id: string; agent_id: string; network: Network; vault_id: string; permit_hash: string;
  receiver_id: string; action_json: string; code_identity: string | null; stage: string; signed: number;
  submitted: number; finalized: number; nonexecution_proven: number; transaction_id: string | null;
  approval_reference: string | null; finalized_at: number | null; updated_at: number;
}

/** SQLite persistence. Methods performing writes use short synchronous transactions only. */
export class GuardStore {
  readonly database: Database.Database;
  constructor(path = ':memory:', options: { manifestPath?: string } = {}) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.database = new Database(path);
    this.database.pragma('foreign_keys = ON');
    this.database.pragma('journal_mode = WAL');
    this.database.pragma('busy_timeout = 5000');
    try { migrate(this.database, options.manifestPath); } catch (error) { this.database.close(); throw error; }
  }
  close(): void { this.database.close(); }
  isHealthy(): boolean {
    try { return (this.database.prepare('SELECT 1 AS ok').get() as { ok: number }).ok === 1; } catch { return false; }
  }
  registerAgent(input: AgentRegistration, now = Date.now()): void {
    const agent = agentRegistrationSchema.parse(input);
    decodePublicKey(agent.public_key);
    const existing = this.database.prepare('SELECT registration_json FROM agents WHERE id = ?').get(agent.agent_id) as { registration_json: string } | undefined;
    if (existing && existing.registration_json !== canonical(agent)) throw new ApiError('REQUEST_CONFLICT', 'Agent registration already exists; rotate credentials explicitly', 409);
    this.database.prepare('INSERT OR IGNORE INTO agents(id, credential_hash, registration_json, created_at) VALUES (?, ?, ?, ?)').run(agent.agent_id, agent.credential_hash, canonical(agent), now);
    const persisted = this.database.prepare('SELECT registration_json FROM agents WHERE id=?').get(agent.agent_id) as { registration_json: string } | undefined;
    if (!persisted || persisted.registration_json !== canonical(agent)) throw new ApiError('REQUEST_CONFLICT', 'Agent identity or credential is already bound to another registration', 409);
  }
  authenticate(hash: string): AgentRegistration | null {
    const row = this.database.prepare('SELECT registration_json FROM agents WHERE credential_hash = ?').get(hash) as { registration_json: string } | undefined;
    return row ? agentRegistrationSchema.parse(JSON.parse(row.registration_json)) : null;
  }
  claim(agent: AgentRegistration, request: CheckRequest, mode: SourceMode, now: number, leaseMs = 30_000): Claim {
    const fingerprint = digest({ network: request.network, vault_id: request.vault_id, action: request.action, source_mode: mode });
    return this.database.transaction(() => {
      const id = randomUUID();
      const nonce = randomBytes(32).toString('hex');
      const owner = randomUUID();
      this.database.prepare(`INSERT OR IGNORE INTO checks(id,agent_id,request_id,network,vault_id,source_mode,action_json,fingerprint,nonce,state,lease_owner,lease_until,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,'claimed',?,?,?)`).run(id, agent.agent_id, request.request_id, request.network, request.vault_id, mode, canonical(request.action), fingerprint, nonce, owner, now + leaseMs, now);
      const row = this.database.prepare('SELECT * FROM checks WHERE agent_id = ? AND request_id = ?').get(agent.agent_id, request.request_id) as CheckRow;
      if (row.fingerprint !== fingerprint) throw new ApiError('REQUEST_CONFLICT', 'Request ID is bound to a different action or context', 409);
      if (row.invalidated_reason) throw new ApiError('CHECK_INVALIDATED', 'Assessment was invalidated; use an explicit new request', 409);
      if (row.state === 'complete') {
        if (row.expires_at === null || row.expires_at <= now) throw new ApiError('CHECK_EXPIRED', 'Assessment expired; use an explicit new request', 409);
        return { id: row.id, nonce: row.nonce, owner: '', cached: checkResponseSchema.parse(JSON.parse(row.response_json!)) };
      }
      if (row.id !== id && row.state === 'claimed' && row.lease_until > now) throw new ApiError('ISSUANCE_IN_PROGRESS', 'Assessment is already being processed; retry this request ID', 409);
      this.database.prepare("UPDATE checks SET state='claimed', lease_owner=?, lease_until=? WHERE id=?").run(owner, now + leaseMs, row.id);
      return { id: row.id, nonce: row.nonce, owner, cached: null };
    })();
  }
  release(claim: Claim): void {
    this.database.prepare("UPDATE checks SET state='failed', lease_owner=NULL, lease_until=0 WHERE id=? AND lease_owner=? AND state='claimed'").run(claim.id, claim.owner);
  }
  complete(claim: Claim, agent: AgentRegistration, request: CheckRequest, snapshot: EvidenceSnapshot, response: CheckResponse): void {
    const result = checkResponseSchema.parse(response);
    if (result.permit && result.permit.payload.evidence_snapshot_hash !== digest(snapshot)) throw new ApiError('EVIDENCE_UNAVAILABLE', 'Retained evidence differs from the signed snapshot', 503);
    if (Buffer.byteLength(canonical(snapshot)) > 1_048_576) throw new ApiError('EVIDENCE_UNAVAILABLE', 'Evidence snapshot exceeds retention limits', 503);
    this.database.transaction(() => {
      const row = this.database.prepare('SELECT * FROM checks WHERE id=?').get(claim.id) as CheckRow;
      if (row.state !== 'claimed' || row.lease_owner !== claim.owner) throw new ApiError('ISSUANCE_IN_PROGRESS', 'Assessment ownership changed; retry this request ID', 409);
      if (row.invalidated_reason) throw new ApiError('CHECK_INVALIDATED', 'Assessment was invalidated during issuance; use an explicit new request', 409);
      const snapshotId = randomUUID();
      this.database.prepare('INSERT INTO evidence_snapshots VALUES (?,?,?,?,?,?,?)').run(snapshotId, request.network, result.source_mode, request.action.receiver_id, digest(snapshot), canonical(snapshot), result.evaluated_at);
      this.database.prepare('INSERT INTO receiver_observations VALUES (?,?,?,?,?,?,?,?)').run(randomUUID(), agent.agent_id, request.network, result.source_mode, request.action.receiver_id, snapshot.evidence.code_identity, snapshotId, snapshot.evidence.observed_at);
      this.database.prepare('INSERT INTO policy_observations VALUES (?,?,?,?,?,?)').run(randomUUID(), agent.agent_id, request.network, snapshot.policy.revision, canonical(snapshot.policy), snapshot.policy.observed_at);
      if (result.permit) {
        this.database.prepare('INSERT INTO permit_records VALUES (?,?,?,?,?,?,?)').run(claim.id, request.network, agent.agent_id, claim.nonce, result.permit.permit_hash, canonical(result.permit), result.evaluated_at);
        this.database.prepare(`INSERT INTO executions(id,check_id,agent_id,network,vault_id,permit_hash,receiver_id,action_json,code_identity,stage,updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,'attempted',?)`).run(claim.id, claim.id, agent.agent_id, request.network, request.vault_id, result.permit.permit_hash, request.action.receiver_id, canonical(request.action), snapshot.evidence.code_identity, result.evaluated_at);
      }
      this.database.prepare("UPDATE checks SET state='complete', response_json=?,snapshot_id=?,expires_at=?,lease_owner=NULL,lease_until=0 WHERE id=?").run(canonical(result), snapshotId, result.expires_at, claim.id);
    })();
  }
  check(id: string, agentId: string): StoredCheck | null {
    const row = this.database.prepare("SELECT * FROM checks WHERE id=? AND agent_id=? AND state='complete'").get(id, agentId) as CheckRow | undefined;
    if (!row) return null;
    const snapshot = this.database.prepare('SELECT snapshot_json FROM evidence_snapshots WHERE id=?').get(row.snapshot_id) as { snapshot_json: string };
    return { row, response: checkResponseSchema.parse(JSON.parse(row.response_json!)), snapshot: JSON.parse(snapshot.snapshot_json) as EvidenceSnapshot };
  }
  invalidate(id: string, reason: string): void {
    this.database.prepare('UPDATE checks SET invalidated_reason=COALESCE(invalidated_reason,?) WHERE id=?').run(reason, id);
  }
  invalidateReceiver(network: Network, accountId: string, reason: string): number {
    return this.database.prepare('UPDATE checks SET invalidated_reason=COALESCE(invalidated_reason,?) WHERE network=? AND json_extract(action_json,\'$.receiver_id\')=?').run(reason, network, accountId).changes;
  }
  history(agent: AgentRegistration, receiverId: string, sourceMode: SourceMode): { finalized_successes: number; approved_code_identity: string | null } {
    const rows = this.database.prepare(`SELECT e.code_identity FROM executions e JOIN checks c ON c.id=e.check_id
      WHERE e.agent_id=? AND e.network=? AND e.vault_id=? AND c.source_mode=? AND e.receiver_id=? AND e.stage='succeeded' AND e.finalized=1
      ORDER BY e.finalized_at DESC LIMIT 100`).all(agent.agent_id, agent.network, agent.vault_id, sourceMode, receiverId) as { code_identity: string | null }[];
    return { finalized_successes: rows.length, approved_code_identity: rows[0]?.code_identity ?? null };
  }
  receiver(agent: AgentRegistration, accountId: string, sourceMode: SourceMode): { evidence: ReceiverEvidence; history: ReturnType<GuardStore['history']> } | null {
    const row = this.database.prepare(`SELECT s.snapshot_json FROM receiver_observations o JOIN evidence_snapshots s ON s.id=o.snapshot_id
      WHERE o.agent_id=? AND o.network=? AND o.source_mode=? AND o.account_id=? ORDER BY o.observed_at DESC LIMIT 1`).get(agent.agent_id, agent.network, sourceMode, accountId) as { snapshot_json: string } | undefined;
    return row ? { evidence: (JSON.parse(row.snapshot_json) as EvidenceSnapshot).evidence, history: this.history(agent, accountId, sourceMode) } : null;
  }
  execution(id: string, agentId: string): (ExecutionRecord & { receipts: ExecutionObservation[] }) | null {
    const row = this.database.prepare('SELECT * FROM executions WHERE id=? AND agent_id=?').get(id, agentId) as ExecutionRecord | undefined;
    if (!row) return null;
    const receipts = this.database.prepare('SELECT receipt_json FROM execution_receipts WHERE execution_id=? ORDER BY observed_at').all(id) as { receipt_json: string }[];
    return { ...row, receipts: receipts.map(receipt => executionObservationSchema.parse(JSON.parse(receipt.receipt_json))) };
  }
  reconcile(input: ExecutionObservation): void {
    const observation = executionObservationSchema.parse(input);
    this.database.transaction(() => {
      const row = this.database.prepare('SELECT * FROM executions WHERE id=?').get(observation.execution_id) as ExecutionRecord | undefined;
      if (!row || row.check_id !== observation.check_id || row.network !== observation.network || row.vault_id !== observation.vault_id || row.permit_hash !== observation.permit_hash) throw new ApiError('INVALID_REQUEST', 'Execution evidence does not bind to the issued permit', 400);
      const isFinal = observation.state === 'succeeded' || observation.state === 'failed';
      if (isFinal && (!observation.finalized || !observation.receipt_id || !observation.block_hash || !observation.block_height || (observation.state === 'failed' && !observation.nonexecution_proven))) throw new ApiError('INVALID_REQUEST', 'Final outcome requires finalized receipt and nonexecution proof for failure', 400);
      if (isFinal && observation.state === 'succeeded') {
        const check = this.check(row.check_id, row.agent_id);
        if (check?.response.decision === 'warn' && !observation.owner_approval_ref) throw new ApiError('INVALID_REQUEST', 'Final warning execution requires independent owner approval evidence', 400);
      }
      if (observation.nonexecution_proven && observation.state !== 'failed') throw new ApiError('INVALID_REQUEST', 'Nonexecution proof cannot accompany this execution state', 400);
      if (!isFinal && observation.finalized) throw new ApiError('INVALID_REQUEST', 'A nonfinal state cannot claim finalization', 400);
      if (isFinal && observation.receipt_id) {
        const hash = digest({ ...observation, observed_at: 0 });
        const prior = this.database.prepare('SELECT execution_id,receipt_hash FROM execution_receipts WHERE network=? AND receipt_id=?').get(observation.network, observation.receipt_id) as { execution_id: string; receipt_hash: string } | undefined;
        if (prior) {
          if (prior.execution_id !== row.id || prior.receipt_hash !== hash) throw new ApiError('REQUEST_CONFLICT', 'Receipt was reused with different execution evidence', 409);
          return;
        }
        this.database.prepare('INSERT INTO execution_receipts VALUES (?,?,?,?,?,?)').run(observation.network, observation.receipt_id, row.id, hash, canonical(observation), observation.observed_at);
      }
      if (row.finalized) {
        if (isFinal && row.stage !== observation.state) throw new ApiError('REQUEST_CONFLICT', 'Conflicting finalized execution outcome', 409);
        return;
      }
      if (!isFinal && observation.observed_at < row.updated_at) return;
      const rank: Record<string, number> = { attempted: 0, signed: 1, submitted: 2, pending: 3, uncertain: 4, succeeded: 5, failed: 5 };
      if (!isFinal && (rank[observation.state] ?? 0) < (rank[row.stage] ?? 0)) return;
      const submitted = ['submitted', 'pending', 'uncertain', 'succeeded', 'failed'].includes(observation.state);
      const signed = observation.state !== 'attempted';
      this.database.prepare(`UPDATE executions SET stage=?,signed=MAX(signed,?),submitted=MAX(submitted,?),finalized=?,nonexecution_proven=?,
        transaction_id=COALESCE(?,transaction_id),approval_reference=COALESCE(?,approval_reference),finalized_at=?,updated_at=? WHERE id=?`).run(
        observation.state, Number(signed), Number(submitted), Number(observation.finalized), Number(observation.nonexecution_proven), observation.transaction_id,
        observation.owner_approval_ref, isFinal ? observation.observed_at : null, Math.max(row.updated_at, observation.observed_at), row.id,
      );
    })();
  }
}
