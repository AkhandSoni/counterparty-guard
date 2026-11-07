import { createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { publicKeyFromKeyObject, signPermit, type ReceiverEvidence } from '@counterparty-guard/shared';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { GuardStore } from './storage/store.js';

/** Standalone local fixture process. Live service assembly injects B/C-owned adapters separately. */
async function start(): Promise<void> {
  const config = loadConfig();
  const key = createPrivateKey(readFileSync(config.fixture.scorer_key_file));
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Expected an Ed25519 scorer key');
  const store = new GuardStore(config.databasePath);
  for (const registration of config.fixture.agents) store.registerAgent(registration);
  const app = createApp({
    store, sourceMode: 'fixture', scorerPublicKey: publicKeyFromKeyObject(key),
    signPermit: payload => signPermit(payload, key),
    receiverProvider: {
      sourceMode: 'fixture',
      async assess(input) {
        const fixture = config.fixture.receivers.find(receiver => receiver.network === input.network && receiver.account_id === input.account_id);
        if (!fixture) throw new Error('Fixture receiver not configured');
        const timestamp = Date.now();
        const evidence: ReceiverEvidence = structuredClone(fixture);
        evidence.observed_at = timestamp;
        // These are visibly fixture observations, never claims of live chain freshness.
        evidence.observations = evidence.observations.map(observation => ({ ...observation, fetched_at: timestamp, source_timestamp: timestamp }));
        return evidence;
      },
    },
    policyProvider: { async getPolicy() { return { ...config.fixture.policy, observed_at: Date.now() }; } },
    reputationProvider: { async getReputation(network, accountId) {
      const reputation = config.fixture.reputations.find(value => value.network === network && value.account_id === accountId);
      if (!reputation) throw new Error('Fixture reputation not configured');
      return { ...reputation, observed_at: Date.now() };
    } },
    ...(config.fixture.reviewer_credential_hash ? { reviewerCredentialHash: config.fixture.reviewer_credential_hash } : {}),
  });
  let closing = false;
  const close = async (): Promise<void> => {
    if (closing) return;
    closing = true;
    await app.close();
    store.close();
  };
  process.once('SIGINT', () => { void close(); });
  process.once('SIGTERM', () => { void close(); });
  try { await app.listen({ host: config.host, port: config.port }); }
  catch (error) { await close(); throw error; }
  process.stdout.write(`Counterparty Guard fixture API listening on ${config.host}:${config.port}; no chain execution configured\n`);
}
start().catch(() => { process.stderr.write('Counterparty Guard could not start; check local configuration and dependency availability\n'); process.exitCode = 1; });
