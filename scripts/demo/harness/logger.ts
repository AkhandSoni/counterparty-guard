/**
 * @file scripts/demo/harness/logger.ts
 * @description Structured JSONL audit logger for demo runners (conforming to PROJECT.md § Interface Contracts 3).
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  DecisionSchema,
  type DemoExecutionLog,
  DemoExecutionLogSchema,
  ScenarioIdSchema,
} from '@counterparty-guard/shared';
import { z } from 'zod';

/**
 * Audit log entry schema conforming strictly to PROJECT.md § Interface Contracts 3.
 */
export const AuditLogRecordSchema = z.object({
  run_id: z.string().uuid(),
  timestamp: z.string().datetime().or(z.string()),
  scenario_id: ScenarioIdSchema,
  mode: z.enum(['deterministic', 'sandbox', 'testnet']),
  injected_prompt_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  decision: DecisionSchema,
  reason_codes: z.array(z.string()),
  permit_hash: z.string().nullable(),
  signed: z.boolean(),
  submitted: z.boolean(),
  finalized_outcome: z.string(),
  receiver_balance_delta: z.string().regex(/^\d+$/),
  // Optional audit metadata fields
  proposed_action: z
    .object({
      kind: z.string(),
      receiver_id: z.string(),
      amount_yocto: z.string().optional(),
      method_name: z.string().optional(),
    })
    .optional(),
  check_id: z.string().optional(),
  error_message: z.string().nullable().optional(),
});

export type AuditLogRecord = z.infer<typeof AuditLogRecordSchema>;

/**
 * Computes deterministic SHA-256 digest of untrusted prompt content.
 * Returns formatted as `sha256:<64-hex>`.
 */
export function hashPrompt(promptText: string): string {
  const digest = createHash('sha256').update(promptText, 'utf-8').digest('hex');
  return `sha256:${digest}`;
}

export interface LoggerOptions {
  logFilePath?: string;
  echoToConsole?: boolean;
  verbose?: boolean;
}

export class JsonlLogger {
  private readonly logFilePath: string;
  private readonly echoToConsole: boolean;
  private readonly verbose: boolean;

  constructor(options: LoggerOptions = {}) {
    this.logFilePath = options.logFilePath ?? 'docs/demo-logs/attack-demo.jsonl';
    this.echoToConsole = options.echoToConsole ?? true;
    this.verbose = options.verbose ?? false;
  }

  public getLogFilePath(): string {
    return this.logFilePath;
  }

  /**
   * Appends an audit log record as a single JSON line to the log file and optionally logs to stdout.
   */
  public writeRecord(record: AuditLogRecord): void {
    // 1. Strict schema validation
    const parsed = AuditLogRecordSchema.parse(record);

    // Also assert compatibility with @counterparty-guard/shared DemoExecutionLogSchema
    DemoExecutionLogSchema.parse(parsed);

    // 2. Prepare single-line JSON string
    const jsonLine = `${JSON.stringify(parsed)}\n`;

    // 3. Ensure target directory exists
    const resolvedPath = path.resolve(this.logFilePath);
    const parentDir = path.dirname(resolvedPath);
    if (!fs.existsSync(parentDir)) {
      fs.mkdirSync(parentDir, { recursive: true });
    }

    // 4. Append to file
    fs.appendFileSync(resolvedPath, jsonLine, 'utf-8');

    // 5. Console output
    if (this.echoToConsole) {
      if (this.verbose) {
        this.printVerboseSummary(parsed);
      } else {
        console.log(`[JSONL AUDIT] ${jsonLine.trim()}`);
      }
    }
  }

  /**
   * Reads and parses all JSONL records from the log file.
   */
  public readRecords(): AuditLogRecord[] {
    const resolvedPath = path.resolve(this.logFilePath);
    if (!fs.existsSync(resolvedPath)) {
      return [];
    }
    const content = fs.readFileSync(resolvedPath, 'utf-8');
    const lines = content.split('\n').filter((l) => l.trim().length > 0);
    return lines.map((line) => AuditLogRecordSchema.parse(JSON.parse(line)));
  }

  /**
   * Clears the current log file.
   */
  public clear(): void {
    const resolvedPath = path.resolve(this.logFilePath);
    if (fs.existsSync(resolvedPath)) {
      fs.writeFileSync(resolvedPath, '', 'utf-8');
    }
  }

  /**
   * Logs a step message if verbose mode is enabled.
   */
  public step(title: string, details?: Record<string, unknown>): void {
    if (!this.verbose) return;
    console.log(`\n▶ [STEP] ${title}`);
    if (details) {
      for (const [k, v] of Object.entries(details)) {
        console.log(`  • ${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`);
      }
    }
  }

  /**
   * Logs a section transcript block if verbose mode is enabled.
   */
  public transcript(title: string, content: string): void {
    if (!this.verbose) return;
    console.log(`\n================= ${title} =================`);
    console.log(content.trim());
    console.log('========================================================\n');
  }

  private printVerboseSummary(record: AuditLogRecord): void {
    console.log('\n┌────────────────────────────────────────────────────────┐');
    console.log('│             AUDIT LOG RECORD SUMMARY                   │');
    console.log('├────────────────────────────────────────────────────────┤');
    console.log(`│ Run ID:       ${record.run_id.padEnd(40)} │`);
    console.log(`│ Timestamp:    ${record.timestamp.padEnd(40)} │`);
    console.log(`│ Scenario:     ${record.scenario_id.padEnd(40)} │`);
    console.log(`│ Mode:         ${record.mode.padEnd(40)} │`);
    console.log(`│ Decision:     ${record.decision.toUpperCase().padEnd(40)} │`);
    console.log(`│ Reason Codes: ${record.reason_codes.join(', ').slice(0, 40).padEnd(40)} │`);
    console.log(
      `│ Permit Hash:  ${(record.permit_hash ?? 'null (NO PERMIT)').slice(0, 40).padEnd(40)} │`,
    );
    console.log(`│ Signed:       ${String(record.signed).toUpperCase().padEnd(40)} │`);
    console.log(`│ Submitted:    ${String(record.submitted).toUpperCase().padEnd(40)} │`);
    console.log(`│ Final Outcome:${record.finalized_outcome.slice(0, 40).padEnd(40)} │`);
    console.log(
      `│ Balance Delta:${`${record.receiver_balance_delta} yocto`.slice(0, 40).padEnd(40)} │`,
    );
    console.log('└────────────────────────────────────────────────────────┘\n');
  }
}

export interface AuditLoggerOptions {
  logFilePath?: string;
  emitStdout?: boolean;
}

export class AuditLogger {
  private logFilePath?: string;
  private emitStdout: boolean;
  private logs: DemoExecutionLog[] = [];

  constructor(options?: AuditLoggerOptions) {
    this.logFilePath = options?.logFilePath;
    this.emitStdout = options?.emitStdout ?? false;
  }

  public log(entry: DemoExecutionLog): void {
    const validated = DemoExecutionLogSchema.parse(entry);
    this.logs.push(validated);
    const line = JSON.stringify(validated);
    if (this.emitStdout) {
      console.log(line);
    }
    if (this.logFilePath) {
      const dir = path.dirname(this.logFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.appendFileSync(this.logFilePath, `${line}\n`, 'utf-8');
    }
  }

  public getLogs(): DemoExecutionLog[] {
    return [...this.logs];
  }

  public clear(): void {
    this.logs = [];
  }
}
