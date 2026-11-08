#!/usr/bin/env tsx
/**
 * @file scripts/demo/run-all.ts
 * @description Comprehensive Scenario Runner for Counterparty Guard Demonstration.
 *
 * Sequentially executes all 10 scenarios S1 through S10 against the specified mode
 * (deterministic, sandbox, or testnet) and verifies critical security invariants.
 *
 * Emits:
 * 1. Structured JSONL audit log conforming to DemoExecutionLogSchema.
 * 2. Pretty-printed terminal table with ANSI colors, latency, outcomes, and assertion counts.
 *
 * Usage:
 *   pnpm demo:all
 *   pnpm demo:all --mode sandbox
 *   pnpm demo:all --scenario S3
 *   pnpm demo:all --json
 *   pnpm demo:all --verbose
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { type ScenarioId, ScenarioIdSchema } from '@counterparty-guard/shared';
import {
  type ExecutionMode,
  type ScenarioExecutionResult,
  createExecutionAdapter,
} from './harness/adapter.js';

export interface RunAllOptions {
  mode?: ExecutionMode;
  scenarioId?: ScenarioId;
  logFilePath?: string;
  jsonOutput?: boolean;
  verbose?: boolean;
  rpcUrl?: string;
}

export interface RunAllSummary {
  mode: ExecutionMode;
  totalScenarios: number;
  passedScenarios: number;
  failedScenarios: number;
  totalAssertions: number;
  passedAssertions: number;
  totalDurationMs: number;
  logFilePath: string;
  results: ScenarioExecutionResult[];
}

// ─────────────────────────────────────────────────────────────────────────────
// ANSI Colors & Terminal Formatting
// ─────────────────────────────────────────────────────────────────────────────

const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[90m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  blue: '\x1b[34m',
  bgDark: '\x1b[40m',
};

function colorDecision(decision: string): string {
  switch (decision.toLowerCase()) {
    case 'allow':
      return `${colors.green}${colors.bold}ALLOW${colors.reset}`;
    case 'warn':
      return `${colors.yellow}${colors.bold}WARN ${colors.reset}`;
    case 'block':
      return `${colors.red}${colors.bold}BLOCK${colors.reset}`;
    default:
      return `${colors.magenta}${colors.bold}${decision.toUpperCase().padEnd(5)}${colors.reset}`;
  }
}

function colorStatus(passed: boolean): string {
  return passed
    ? `${colors.green}${colors.bold}PASS${colors.reset}`
    : `${colors.red}${colors.bold}FAIL${colors.reset}`;
}

function colorBool(val: boolean): string {
  return val ? `${colors.green}true ${colors.reset}` : `${colors.dim}false${colors.reset}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Programmatic Runner
// ─────────────────────────────────────────────────────────────────────────────

export async function runAllScenarios(options: RunAllOptions = {}): Promise<RunAllSummary> {
  const mode: ExecutionMode = options.mode ?? 'deterministic';
  const startTime = performance.now();

  const allScenarios: ScenarioId[] = options.scenarioId
    ? [options.scenarioId]
    : ['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9', 'S10'];

  const defaultLogDir = path.resolve(process.cwd(), 'docs/demo-logs');
  const logFilePath = options.logFilePath ?? path.join(defaultLogDir, `demo-all-${mode}.jsonl`);

  // Ensure log directory exists
  if (!fs.existsSync(path.dirname(logFilePath))) {
    fs.mkdirSync(path.dirname(logFilePath), { recursive: true });
  }

  // Clear existing log file for this run
  fs.writeFileSync(logFilePath, '', 'utf-8');

  const adapter = createExecutionAdapter(mode, {
    rpcUrl: options.rpcUrl,
    fallbackToDeterministic: true,
  });

  await adapter.init();

  const results: ScenarioExecutionResult[] = [];

  for (const scenarioId of allScenarios) {
    const result = await adapter.executeScenario(scenarioId, {
      verbose: options.verbose,
    });
    results.push(result);

    // Append JSONL audit record to file
    const logLine = JSON.stringify(result.log);
    fs.appendFileSync(logFilePath, `${logLine}\n`, 'utf-8');

    if (options.jsonOutput) {
      console.log(logLine);
    }
  }

  await adapter.teardown();

  const totalDurationMs = performance.now() - startTime;
  const passedScenarios = results.filter((r) => r.passed).length;
  const failedScenarios = results.length - passedScenarios;
  const totalAssertions = results.reduce((acc, r) => acc + r.assertionsTotal, 0);
  const passedAssertions = results.reduce((acc, r) => acc + r.assertionsPassed, 0);

  return {
    mode,
    totalScenarios: results.length,
    passedScenarios,
    failedScenarios,
    totalAssertions,
    passedAssertions,
    totalDurationMs,
    logFilePath,
    results,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Pretty-Printed Terminal Table Renderer
// ─────────────────────────────────────────────────────────────────────────────

export function printTerminalReport(
  summary: RunAllSummary,
  options: { verbose?: boolean } = {},
): void {
  const line = '═'.repeat(102);
  const divider = '─'.repeat(102);

  console.log(
    `\n${colors.cyan}${colors.bold}🛡️  COUNTERPARTY GUARD — COMPREHENSIVE DEMO RUNNER${colors.reset}`,
  );
  console.log(
    `${colors.dim}Target Mode: ${summary.mode.toUpperCase()} | Scenarios: ${summary.totalScenarios} | Time: ${new Date().toISOString()}${colors.reset}\n`,
  );
  console.log(line);
  console.log(
    ` ${colors.bold}${'ID'.padEnd(4)}  ${'Scenario Name'.padEnd(30)}  ${'Decision'.padEnd(8)}  ${'Signed'.padEnd(6)}  ${'Subm'.padEnd(6)}  ${'Finalized Outcome'.padEnd(23)}  ${'Asserts'.padEnd(8)}  ${'Latency'.padEnd(7)}  ${'Status'}${colors.reset}`,
  );
  console.log(divider);

  for (const r of summary.results) {
    const idStr = r.scenarioId.padEnd(4);
    const nameStr = (r.name.length > 30 ? `${r.name.slice(0, 27)}...` : r.name).padEnd(30);
    const decStr = colorDecision(r.log.decision).padEnd(17);
    const signedStr = colorBool(r.log.signed).padEnd(15);
    const submStr = colorBool(r.log.submitted).padEnd(15);
    const outcomeStr = (
      r.log.finalized_outcome.length > 23
        ? `${r.log.finalized_outcome.slice(0, 20)}...`
        : r.log.finalized_outcome
    ).padEnd(23);
    const assertsStr = `${r.assertionsPassed}/${r.assertionsTotal}`.padEnd(8);
    const latStr = `${r.durationMs.toFixed(1)}ms`.padEnd(7);
    const statStr = colorStatus(r.passed);

    console.log(
      ` ${idStr}  ${nameStr}  ${decStr}  ${signedStr}  ${submStr}  ${colors.dim}${outcomeStr}${colors.reset}  ${assertsStr}  ${colors.cyan}${latStr}${colors.reset}  ${statStr}`,
    );

    if (options.verbose || !r.passed) {
      for (const a of r.assertions) {
        const icon = a.passed ? `${colors.green}✓${colors.reset}` : `${colors.red}✗${colors.reset}`;
        console.log(
          `      ${icon} ${colors.dim}${a.name}: expected ${JSON.stringify(a.expected)}, got ${JSON.stringify(a.actual)}${colors.reset}`,
        );
        if (!a.passed && a.message) {
          console.log(`        ${colors.red}Error: ${a.message}${colors.reset}`);
        }
      }
    }
  }

  console.log(line);

  // Summary Banner
  if (summary.failedScenarios === 0) {
    console.log(
      `${colors.green}${colors.bold}✅ ALL SCENARIOS PASSED:${colors.reset} ${summary.passedScenarios}/${summary.totalScenarios} scenarios succeeded (${summary.passedAssertions}/${summary.totalAssertions} assertions verified)`,
    );
  } else {
    console.log(
      `${colors.red}${colors.bold}❌ SCENARIOS FAILED:${colors.reset} ${summary.failedScenarios}/${summary.totalScenarios} failed (${summary.passedAssertions}/${summary.totalAssertions} assertions passed)`,
    );
  }

  console.log(
    `${colors.dim}Total Elapsed Time: ${summary.totalDurationMs.toFixed(2)}ms | Mode: ${summary.mode} | Log File: ${summary.logFilePath}${colors.reset}\n`,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI Entry Point
// ─────────────────────────────────────────────────────────────────────────────

function parseCliArgs(): RunAllOptions {
  const args = process.argv.slice(2);
  const options: RunAllOptions = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      console.log(`
Counterparty Guard Comprehensive Demo Runner

Usage:
  tsx scripts/demo/run-all.ts [options]

Options:
  --mode <mode>        Execution mode: deterministic (default), sandbox, testnet
  --scenario <id>      Run single scenario: S1 through S10
  --log-file <path>    Custom output path for JSONL audit log
  --json               Output only JSONL logs to stdout
  --verbose, -v        Print detailed assertion breakdowns
  --rpc <url>          Custom RPC URL for sandbox or testnet
  --help, -h           Show this help message
`);
      process.exit(0);
    } else if (arg === '--mode') {
      const modeVal = args[++i];
      if (modeVal === 'deterministic' || modeVal === 'sandbox' || modeVal === 'testnet') {
        options.mode = modeVal;
      } else {
        console.error(`Invalid mode "${modeVal}". Expected deterministic, sandbox, or testnet.`);
        process.exit(1);
      }
    } else if (arg === '--scenario') {
      const sId = args[++i]?.toUpperCase();
      const parseResult = ScenarioIdSchema.safeParse(sId);
      if (parseResult.success) {
        options.scenarioId = parseResult.data;
      } else {
        console.error(`Invalid scenario ID "${sId}". Expected S1 through S10.`);
        process.exit(1);
      }
    } else if (arg === '--log-file') {
      options.logFilePath = args[++i];
    } else if (arg === '--json') {
      options.jsonOutput = true;
    } else if (arg === '--verbose' || arg === '-v') {
      options.verbose = true;
    } else if (arg === '--rpc') {
      options.rpcUrl = args[++i];
    }
  }

  return options;
}

const isMainModule = (): boolean => {
  try {
    if (!process.argv[1]) return false;
    return (
      path.resolve(process.argv[1]) === fileURLToPath(import.meta.url) ||
      process.argv[1].endsWith('run-all.ts') ||
      process.argv[1].endsWith('run-all.js')
    );
  } catch {
    return false;
  }
};

if (isMainModule()) {
  const options = parseCliArgs();
  runAllScenarios(options)
    .then((summary) => {
      if (!options.jsonOutput) {
        printTerminalReport(summary, { verbose: options.verbose });
      }
      process.exit(summary.failedScenarios > 0 ? 1 : 0);
    })
    .catch((err) => {
      console.error('Fatal error during demo scenario execution:', err);
      process.exit(1);
    });
}
