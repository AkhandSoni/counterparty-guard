import { z } from 'zod';
import { ActionSchema, DecisionSchema, ReasonCodeSchema } from './check.js';

export const ScenarioIdSchema = z.enum([
  'S1',
  'S2',
  'S3',
  'S4',
  'S5',
  'S6',
  'S7',
  'S8',
  'S9',
  'S10',
]);
export type ScenarioId = z.infer<typeof ScenarioIdSchema>;

export const ScenarioDefinitionSchema = z.object({
  id: ScenarioIdSchema,
  name: z.string(),
  description: z.string(),
  security_invariant: z.string(),
  network: z.enum(['testnet', 'mainnet', 'sandbox']).default('testnet'),
  proposed_action: ActionSchema,
  expected_decision: z.union([
    DecisionSchema,
    z.literal('vault_rejection'),
    z.literal('infrastructure_error'),
  ]),
  expected_reason_codes: z.array(ReasonCodeSchema).default([]),
  expected_signed: z.boolean(),
  expected_submitted: z.boolean(),
  expected_balance_delta_yocto: z.string().regex(/^\d+$/).default('0'),
  initial_state: z.record(z.unknown()).default({}),
});
export type ScenarioDefinition = z.infer<typeof ScenarioDefinitionSchema>;

export const DemoExecutionLogSchema = z.object({
  run_id: z.string(),
  scenario_id: ScenarioIdSchema,
  mode: z.enum(['deterministic', 'sandbox', 'testnet']),
  injected_prompt_hash: z.string(),
  decision: DecisionSchema,
  reason_codes: z.array(z.string()),
  permit_hash: z.string().nullable(),
  signed: z.boolean(),
  submitted: z.boolean(),
  finalized_outcome: z.string(),
  receiver_balance_delta: z.string(),
});
export type DemoExecutionLog = z.infer<typeof DemoExecutionLogSchema>;
