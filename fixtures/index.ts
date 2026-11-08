/**
 * @file fixtures/index.ts
 * @description Canonical Deterministic Scenario Fixtures (S1 through S10) and Loader Utilities.
 */

import {
  type Action,
  type Decision,
  type DemoExecutionLog,
  type ExecutionPermit,
  type ReasonCode,
  type ReportRecord,
  ReportRecordSchema,
  type ScenarioDefinition,
  ScenarioDefinitionSchema,
  type ScenarioId,
  ScenarioIdSchema,
} from '@counterparty-guard/shared';

// Re-export shared types for consumers
export type {
  ScenarioId,
  ScenarioDefinition,
  DemoExecutionLog,
  Action,
  Decision,
  ReasonCode,
  ReportRecord,
  ExecutionPermit,
};

export const CANONICAL_SCENARIO_IDS: readonly ScenarioId[] = [
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
] as const;

// Import JSON fixtures
import s1Json from './s1_legitimate_established.json' with { type: 'json' };
import s2Json from './s2_legitimate_new.json' with { type: 'json' };
import s3Json from './s3_reviewed_malicious.json' with { type: 'json' };
import s4Json from './s4_false_report_flood.json' with { type: 'json' };
import s5Json from './s5_circular_activity.json' with { type: 'json' };
import s6Json from './s6_shared_faucet.json' with { type: 'json' };
import s7Json from './s7_upgraded_contract.json' with { type: 'json' };
import s8Json from './s8_permit_replay.json' with { type: 'json' };
import s9Json from './s9_provider_outage.json' with { type: 'json' };
import s10Json from './s10_supported_call.json' with { type: 'json' };

/**
 * Validated canonical scenario fixture constants.
 */
export const s1Fixture: ScenarioDefinition = ScenarioDefinitionSchema.parse(s1Json);
export const s2Fixture: ScenarioDefinition = ScenarioDefinitionSchema.parse(s2Json);
export const s3Fixture: ScenarioDefinition = ScenarioDefinitionSchema.parse(s3Json);
export const s4Fixture: ScenarioDefinition = ScenarioDefinitionSchema.parse(s4Json);
export const s5Fixture: ScenarioDefinition = ScenarioDefinitionSchema.parse(s5Json);
export const s6Fixture: ScenarioDefinition = ScenarioDefinitionSchema.parse(s6Json);
export const s7Fixture: ScenarioDefinition = ScenarioDefinitionSchema.parse(s7Json);
export const s8Fixture: ScenarioDefinition = ScenarioDefinitionSchema.parse(s8Json);
export const s9Fixture: ScenarioDefinition = ScenarioDefinitionSchema.parse(s9Json);
export const s10Fixture: ScenarioDefinition = ScenarioDefinitionSchema.parse(s10Json);

/**
 * Internal map of all canonical scenario fixtures.
 */
const SCENARIO_FIXTURES_MAP: Record<ScenarioId, ScenarioDefinition> = {
  S1: s1Fixture,
  S2: s2Fixture,
  S3: s3Fixture,
  S4: s4Fixture,
  S5: s5Fixture,
  S6: s6Fixture,
  S7: s7Fixture,
  S8: s8Fixture,
  S9: s9Fixture,
  S10: s10Fixture,
};

/**
 * Loads a validated scenario fixture by its canonical ID (S1 through S10).
 * Throws a typed ZodError if the fixture fails schema validation, or Error if not found.
 */
export function loadScenarioFixture(id: ScenarioId | string): ScenarioDefinition {
  const validId = ScenarioIdSchema.parse(id);
  const fixture = SCENARIO_FIXTURES_MAP[validId];
  if (!fixture) {
    throw new Error(`Scenario fixture with ID "${id}" was not found.`);
  }
  return fixture;
}

/**
 * Returns all canonical scenario fixtures as a Record keyed by ScenarioId.
 */
export function getAllScenarioFixtures(): Record<ScenarioId, ScenarioDefinition> {
  return { ...SCENARIO_FIXTURES_MAP };
}

/**
 * Returns array of all canonical scenario fixtures.
 */
export function listScenarioFixtures(): ScenarioDefinition[] {
  return CANONICAL_SCENARIO_IDS.map((id) => SCENARIO_FIXTURES_MAP[id]);
}

/**
 * Extracts target receiver account ID for a given scenario.
 */
export function getScenarioReceiver(id: ScenarioId): string {
  const sc = loadScenarioFixture(id);
  return sc.proposed_action.receiver_id;
}

/**
 * Extracts expected decision verdict for a given scenario.
 */
export function getScenarioExpectedDecision(
  id: ScenarioId,
): Decision | 'vault_rejection' | 'infrastructure_error' {
  const sc = loadScenarioFixture(id);
  return sc.expected_decision;
}

/**
 * Extracts initial state reports for a given scenario, validating against ReportRecordSchema.
 */
export function getScenarioReports(id: ScenarioId): ReportRecord[] {
  const sc = loadScenarioFixture(id);
  const rawReports = (sc.initial_state as { reports?: unknown[] }).reports;
  if (!Array.isArray(rawReports)) {
    return [];
  }
  return rawReports.map((r) => ReportRecordSchema.parse(r));
}

/**
 * Extracts initial canonical permit from a scenario fixture if present.
 */
export function getScenarioCanonicalPermit(id: ScenarioId): {
  permit_hash: string;
  verdict: 'allow' | 'warn';
  nonce: string;
  policy_revision: number;
  blocklist_revision: number;
} | null {
  const sc = loadScenarioFixture(id);
  const permit = (sc.initial_state as { canonical_permit?: unknown }).canonical_permit;
  if (!permit || typeof permit !== 'object') {
    return null;
  }
  return permit as {
    permit_hash: string;
    verdict: 'allow' | 'warn';
    nonce: string;
    policy_revision: number;
    blocklist_revision: number;
  };
}
