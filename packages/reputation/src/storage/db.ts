import { createRequire } from 'node:module';
import type { DatabaseSync } from 'node:sqlite';

const require = createRequire(import.meta.url);
const { DatabaseSync: NodeDatabaseSync } = require('node:sqlite') as {
  DatabaseSync: typeof DatabaseSync;
};

export interface DatabaseOptions {
  path?: string; // ':memory:' or file path
  busyTimeout?: number;
}

export function createDatabase(options: DatabaseOptions = {}): DatabaseSync {
  const dbPath = options.path ?? ':memory:';
  const db = new NodeDatabaseSync(dbPath);

  // Critical PRAGMAs for ACID, integrity, and concurrency
  db.exec('PRAGMA foreign_keys = ON;');
  if (dbPath !== ':memory:') {
    db.exec('PRAGMA journal_mode = WAL;');
    db.exec('PRAGMA synchronous = NORMAL;');
  }
  db.exec(`PRAGMA busy_timeout = ${options.busyTimeout ?? 5000};`);

  return db;
}
