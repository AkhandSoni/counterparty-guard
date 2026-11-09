import { z } from 'zod';

export const DecisionSchema = z.enum(['allow', 'warn', 'block']);
export type Decision = z.infer<typeof DecisionSchema>;

export const TransferActionSchema = z.object({
  kind: z.literal('transfer_near'),
  receiver_id: z.string().min(2).max(64),
  amount_yocto: z.string().regex(/^\d+$/),
});
export type TransferAction = z.infer<typeof TransferActionSchema>;

export const ContractCallActionSchema = z.object({
  kind: z.literal('contract_call'),
  receiver_id: z.string().min(2).max(64),
  method_name: z.string().min(1).max(128),
  args_base64: z.string(),
  attached_deposit_yocto: z.string().regex(/^\d+$/).default('0'),
  gas_tgas: z.number().positive().max(300).default(30),
});
export type ContractCallAction = z.infer<typeof ContractCallActionSchema>;

export const ActionSchema = z.discriminatedUnion('kind', [
  TransferActionSchema,
  ContractCallActionSchema,
]);
export type Action = z.infer<typeof ActionSchema>;

export const ReasonCodeSchema = z.enum([
  'ACTIVE_BLOCK',
  'REVIEWED_BLOCKLIST_MATCH',
  'CODE_CHANGED',
  'RECENT_DEPLOYMENT',
  'DEPENDENT_REPORTS',
  'CIRCULAR_ACTIVITY',
  'COMMON_FAUCET_EXEMPTED',
  'UNKNOWN_AGE',
  'INCOMPLETE_HISTORY',
  'MANDATORY_SOURCE_UNAVAILABLE',
  'POLICY_LIMIT_EXCEEDED',
]);
export type ReasonCode = z.infer<typeof ReasonCodeSchema>;

export const CheckRequestSchema = z.object({
  schema_version: z.literal(1).default(1),
  network: z.enum(['testnet', 'mainnet', 'sandbox']),
  vault_id: z.string().min(2).max(64),
  request_id: z.string().min(1).max(64),
  action: ActionSchema,
});
export type CheckRequest = z.infer<typeof CheckRequestSchema>;

export const ExecutionPermitSchema = z.object({
  permit_hash: z.string().regex(/^[a-f0-9]{64}$/),
  encoded_permit_base64: z.string(),
  signature: z.string().regex(/^ed25519:[1-9A-HJ-NP-Za-km-z]{86,88}$/),
  verdict: z.enum(['allow', 'warn']),
  nonce: z.string(),
  issued_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
});
export type ExecutionPermit = z.infer<typeof ExecutionPermitSchema>;

export const CheckResponseSchema = z.object({
  check_id: z.guid(),
  schema_version: z.number().int().default(1),
  agent_id: z.string(),
  decision: DecisionSchema,
  risk_indicator: z.number().int().min(0).max(100),
  reason_codes: z.array(ReasonCodeSchema),
  reasons: z.array(z.string()),
  evidence_refs: z.array(z.string()),
  coverage: z.object({
    accounts_visited: z.number().int(),
    edges_traversed: z.number().int(),
    truncated: z.boolean(),
    window_days: z.number().int(),
  }),
  source_mode: z.enum(['fixture', 'sandbox', 'testnet']),
  evaluated_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
  policy_revision: z.number().int(),
  blocklist_revision: z.number().int(),
  permit: ExecutionPermitSchema.nullable(),
  attestation: z.null().default(null),
});
export type CheckResponse = z.infer<typeof CheckResponseSchema>;
