import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { z } from 'zod';
import { agentRegistrationSchema, policySnapshotSchema, receiverEvidenceSchema, reputationSnapshotSchema } from '@counterparty-guard/shared';

export const fixtureConfigSchema = z.strictObject({
  source_mode: z.literal('fixture'),
  agents: z.array(agentRegistrationSchema).min(1).max(100),
  policy: policySnapshotSchema,
  receivers: z.array(receiverEvidenceSchema).min(1).max(100),
  reputations: z.array(reputationSnapshotSchema).min(1).max(100),
  scorer_key_file: z.string().min(1).max(4096),
  database_path: z.string().min(1).max(4096).optional(),
  reviewer_credential_hash: z.string().regex(/^[0-9a-f]{64}$/).optional(),
});
export type FixtureConfig = z.infer<typeof fixtureConfigSchema>;

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): { fixture: FixtureConfig; host: string; port: number; databasePath: string } {
  if (environment.SOURCE_MODE && environment.SOURCE_MODE !== 'fixture') throw new Error('Live mode requires injected verified policy, reputation and finality adapters through createApp; the standalone fixture server cannot issue live permits');
  if (!environment.GUARD_CONFIG_FILE) throw new Error('GUARD_CONFIG_FILE is required; run the documented local setup');
  const file = resolve(environment.GUARD_CONFIG_FILE);
  if (statSync(file).size > 2_097_152) throw new Error('Configuration exceeds input bound');
  const fixture = fixtureConfigSchema.parse(JSON.parse(readFileSync(file, 'utf8')));
  if (fixture.policy.network !== 'sandbox' || fixture.agents.some(agent => agent.network !== 'sandbox') || fixture.receivers.some(receiver => receiver.network !== 'sandbox' || receiver.source_mode !== 'fixture') || fixture.reputations.some(reputation => reputation.network !== 'sandbox')) throw new Error('Standalone fixture server is restricted to sandbox credentials and evidence');
  const rawPort = environment.API_PORT ?? '3000';
  if (!/^[0-9]{1,5}$/.test(rawPort) || Number(rawPort) < 1 || Number(rawPort) > 65535) throw new Error('Invalid API_PORT');
  const host = environment.API_HOST ?? '127.0.0.1';
  if (!['127.0.0.1', '::1', 'localhost'].includes(host)) throw new Error('Standalone fixture server binds only to loopback');
  return { fixture, host, port: Number(rawPort), databasePath: resolve(environment.DATABASE_PATH ?? fixture.database_path ?? 'artifacts/local/guard.sqlite') };
}
