import Database from 'better-sqlite3';
export type DatabaseSync = Database.Database;
export interface DatabaseOptions { path?: string; busyTimeout?: number; }
export function createDatabase(options: DatabaseOptions = {}): DatabaseSync {
  const db = new Database(options.path ?? ':memory:');
  db.pragma('foreign_keys = ON');
  db.pragma('journal_mode = WAL');
  db.pragma(`busy_timeout = ${options.busyTimeout ?? 5000}`);
  return db;
}
