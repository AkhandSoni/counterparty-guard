import { z } from 'zod';
import { decodePublicKey } from './permit/base58.js';
import { isBoundedJson } from './json.js';

export const U128_MAX = (1n << 128n) - 1n;
export const U64_MAX = (1n << 64n) - 1n;
export const MAX_ARGUMENT_BYTES = 4096;
export const MAX_PERMIT_BYTES = 8192;
export const MAX_PERMIT_TTL_MS = 300_000;
export const PERMIT_DOMAIN = 'CounterpartyGuard/Permit' as const;
export const SIGNING_DOMAIN = 'CounterpartyGuard/PermitSignature/v1\0' as const;
export const networkSchema = z.enum(['sandbox', 'testnet']);
export const sourceModeSchema = z.enum(['fixture', 'live-testnet']);
export const timestampSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
export const revisionSchema = z.string().regex(/^(0|[1-9][0-9]{0,19})$/).refine(value => /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= U64_MAX, 'u64 overflow');
export const amountSchema = z.string().regex(/^(0|[1-9][0-9]{0,38})$/).refine(value => /^(0|[1-9][0-9]{0,38})$/.test(value) && BigInt(value) <= U128_MAX, 'u128 overflow');
export const accountIdSchema = z.string().min(2).max(64).regex(/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/);
export const hex32Schema = z.string().regex(/^[0-9a-f]{64}$/);
export const publicKeySchema = z.string().min(40).max(52).refine(value => { try { decodePublicKey(value); return true; } catch { return false; } }, 'Expected canonical 32-byte Ed25519 key');
export const base64Schema = z.string().max(Math.ceil(MAX_ARGUMENT_BYTES / 3) * 4).refine(value => value.length <= Math.ceil(MAX_ARGUMENT_BYTES / 3) * 4 && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value) && btoa(atob(value)) === value && atob(value).length <= MAX_ARGUMENT_BYTES, 'Expected canonical bounded base64');

export const transferActionSchema = z.strictObject({ kind: z.literal('transfer_near'), receiver_id: accountIdSchema, amount_yocto: amountSchema });
export const contractCallActionSchema = z.strictObject({ kind: z.literal('contract_call'), receiver_id: accountIdSchema, method_name: z.string().min(1).max(64).regex(/^[A-Za-z_][A-Za-z0-9_]*$/), args_base64: base64Schema, attached_deposit_yocto: amountSchema, gas_tgas: z.number().int().min(1).max(300) });
export const actionSchema = z.discriminatedUnion('kind', [transferActionSchema, contractCallActionSchema]);
export const checkRequestSchema = z.strictObject({ schema_version: z.literal(1), network: networkSchema, vault_id: accountIdSchema, request_id: z.string().min(1).max(128).regex(/^[A-Za-z0-9._:-]+$/), action: actionSchema });
export const coverageSchema = z.strictObject({ complete: z.boolean(), truncated: z.boolean(), pages: z.number().int().nonnegative().max(100), window_start_ms: timestampSchema.nullable(), window_end_ms: timestampSchema.nullable(), notes: z.array(z.string().max(256)).max(32) });
export const observationSchema = z.strictObject({ id: z.string().min(1).max(128), kind: z.string().min(1).max(64), network: networkSchema, source_mode: sourceModeSchema, source: z.string().min(1).max(256), fetched_at: timestampSchema, source_timestamp: timestampSchema.nullable(), block_height: revisionSchema.nullable(), block_hash: z.string().min(1).max(128).nullable(), coverage: coverageSchema, raw_hash: hex32Schema, value: z.unknown().refine(isBoundedJson, 'Expected retained bounded JSON evidence') });
export const receiverEvidenceSchema = z.strictObject({ network: networkSchema, source_mode: sourceModeSchema, account_id: accountIdSchema, exists: z.boolean(), code_identity: z.string().min(1).max(128).nullable(), account_age_days: z.number().finite().nonnegative().nullable(), recent_deployment: z.boolean(), independent_successful_counterparties: z.number().int().nonnegative().max(500), transfer_count: z.number().int().nonnegative().max(500), activity_manipulation_score: z.number().int().min(0).max(30), observations: z.array(observationSchema).max(64), coverage: coverageSchema, observed_at: timestampSchema });
export const activeBlockSchema = z.strictObject({ id: z.string().min(1).max(128), network: networkSchema, account_id: accountIdSchema, code_identity: z.string().max(128).nullable(), expires_at: timestampSchema, reviewed_by: z.string().min(1).max(128), evidence_refs: z.array(z.string().min(1).max(256)).min(1).max(32) });
export const reputationSnapshotSchema = z.strictObject({ network: networkSchema, account_id: accountIdSchema, blocklist_revision: revisionSchema, observed_at: timestampSchema, available: z.boolean(), independent_activity_credit: z.number().int().min(0).max(15).optional(), active_blocks: z.array(activeBlockSchema).max(100), unresolved_report_weight: z.number().int().min(0).max(10), dependent_report_groups: z.number().int().nonnegative().max(100), manipulation_score: z.number().int().min(0).max(30), explanations: z.array(z.string().max(512)).max(32), coverage: coverageSchema });
export const supportedCallSchema = z.strictObject({ receiver_id: accountIdSchema, method_name: z.string().min(1).max(64), max_gas_tgas: z.number().int().min(1).max(300), max_deposit_yocto: amountSchema, argument_schema: z.literal('memo-v1') });
export const memoArgumentsSchema = z.strictObject({ memo: z.string().max(256) });
export const policySnapshotSchema = z.strictObject({ network: networkSchema, vault_id: accountIdSchema, deployment_instance_id: hex32Schema, revision: revisionSchema, observed_at: timestampSchema, paused: z.boolean(), max_action_yocto: amountSchema, permit_ttl_ms: z.number().int().min(1).max(MAX_PERMIT_TTL_MS), max_source_age_ms: z.number().int().min(1).max(60_000), supported_call: supportedCallSchema.nullable() });
export const agentRegistrationSchema = z.strictObject({ agent_id: z.string().min(1).max(128), account_id: accountIdSchema, public_key: publicKeySchema, credential_hash: hex32Schema, network: networkSchema, vault_id: accountIdSchema });
export const permitSchema = z.strictObject({ domain: z.literal(PERMIT_DOMAIN), version: z.literal(1), network: networkSchema, deployment_instance_id: hex32Schema, vault_id: accountIdSchema, agent_account_id: accountIdSchema, agent_public_key: publicKeySchema, action: actionSchema, policy_revision: revisionSchema, blocklist_revision: revisionSchema, evidence_snapshot_hash: hex32Schema, verdict: z.enum(['allow', 'warn']), nonce: hex32Schema, issued_at: timestampSchema, expires_at: timestampSchema }).refine(value => value.expires_at > value.issued_at && value.expires_at - value.issued_at <= MAX_PERMIT_TTL_MS, 'Invalid permit lifetime');
export const signedPermitSchema = z.strictObject({ payload: permitSchema, permit_hash: hex32Schema, signature_base64: z.string().length(88), scorer_public_key: publicKeySchema });
export const reasonCodes = ['REVIEWED_BLOCKLIST_MATCH', 'CODE_CHANGED', 'RECENT_DEPLOYMENT', 'DEPENDENT_REPORTS', 'CIRCULAR_ACTIVITY', 'UNKNOWN_AGE', 'NEW_ACCOUNT', 'SPARSE_ACTIVITY', 'INCOMPLETE_HISTORY', 'INDEPENDENT_ACTIVITY', 'FINALIZED_AGENT_HISTORY', 'UNRESOLVED_REPORT', 'BASELINE_UNCERTAINTY'] as const;
export const reasonCodeSchema = z.enum(reasonCodes);
export const decisionSchema = z.enum(['allow', 'warn', 'block']);
export const contributionSchema = z.strictObject({ code: reasonCodeSchema, points: z.number().int().min(-100).max(100), explanation: z.string().min(1).max(512), evidence_refs: z.array(z.string().max(256)).max(64) });
export const scoreResultSchema = z.strictObject({ decision: decisionSchema, risk_indicator: z.number().int().min(0).max(100), reason_codes: z.array(reasonCodeSchema), reasons: z.array(z.string().max(512)), contributions: z.array(contributionSchema) });
export const checkResponseSchema = z.strictObject({ schema_version: z.literal(1), check_id: z.string().min(1).max(128), agent_id: z.string().min(1).max(128), decision: decisionSchema, risk_indicator: z.number().int().min(0).max(100), reason_codes: z.array(reasonCodeSchema), reasons: z.array(z.string().max(512)), contributions: z.array(contributionSchema), evidence_refs: z.array(z.string().max(256)), coverage: coverageSchema, source_mode: sourceModeSchema, evaluated_at: timestampSchema, expires_at: timestampSchema, policy_revision: revisionSchema, blocklist_revision: revisionSchema, permit: signedPermitSchema.nullable(), attestation: z.null() }).refine(value => value.decision === 'block' ? value.permit === null : value.permit !== null && value.permit.payload.verdict === value.decision, 'Verdict and permit mismatch');
export const executionStateSchema = z.enum(['attempted', 'signed', 'submitted', 'pending', 'succeeded', 'failed', 'uncertain']);
export const executionObservationSchema = z.strictObject({ execution_id: z.string().min(1).max(128), check_id: z.string().min(1).max(128), network: networkSchema, vault_id: accountIdSchema, permit_hash: hex32Schema, state: executionStateSchema, transaction_id: z.string().max(128).nullable(), receipt_id: z.string().max(128).nullable(), block_height: revisionSchema.nullable(), block_hash: z.string().max(128).nullable(), observed_at: timestampSchema, finalized: z.boolean(), nonexecution_proven: z.boolean(), owner_approval_ref: z.string().max(256).nullable() });

export type Network = z.infer<typeof networkSchema>;
export type SourceMode = z.infer<typeof sourceModeSchema>;
export type Action = z.infer<typeof actionSchema>;
export type CheckRequest = z.infer<typeof checkRequestSchema>;
export type Coverage = z.infer<typeof coverageSchema>;
export type SourceObservation = z.infer<typeof observationSchema>;
export type ReceiverEvidence = z.infer<typeof receiverEvidenceSchema>;
export type ActiveBlock = z.infer<typeof activeBlockSchema>;
export type ReputationSnapshot = z.infer<typeof reputationSnapshotSchema>;
export type PolicySnapshot = z.infer<typeof policySnapshotSchema>;
export type AgentRegistration = z.infer<typeof agentRegistrationSchema>;
export type Permit = z.infer<typeof permitSchema>;
export type SignedPermit = z.infer<typeof signedPermitSchema>;
export type ReasonCode = z.infer<typeof reasonCodeSchema>;
export type ScoreResult = z.infer<typeof scoreResultSchema>;
export type CheckResponse = z.infer<typeof checkResponseSchema>;
export type ExecutionState = z.infer<typeof executionStateSchema>;
export type ExecutionObservation = z.infer<typeof executionObservationSchema>;
export interface ReceiverQuery { network: Network; account_id: string; action: Action; refresh?: boolean; }
export interface ReceiverProvider { readonly sourceMode: SourceMode; assess(input: ReceiverQuery): Promise<ReceiverEvidence>; }
export interface ReputationProvider { getReputation(network: Network, accountId: string, evidence: ReceiverEvidence): Promise<ReputationSnapshot>; }
export interface PolicyProvider { getPolicy(agent: AgentRegistration): Promise<PolicySnapshot>; }
export interface ExecutionProvider { getExecution(network: Network, vaultId: string, executionId: string): Promise<ExecutionObservation>; }

export type ReputationResult = ReputationSnapshot;
export type ScoringResult = ScoreResult;
export interface ScoringInput { action: Action; evidence: ReceiverEvidence; reputation: ReputationSnapshot; policy: PolicySnapshot; now: number; history: { finalized_successes: number; approved_code_identity: string | null }; }
