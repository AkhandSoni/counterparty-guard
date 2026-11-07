import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type Database from 'better-sqlite3';

export const defaultMigrationManifest = fileURLToPath(new URL('../../../../db/migrations.json', import.meta.url));

/** One ordered manifest owns both core and report migrations; applied SQL is immutable. */
export function migrate(database: Database.Database, manifestPath = defaultMigrationManifest): void {
  const root = dirname(resolve(manifestPath));
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
    version?: unknown; migrations?: { id: string; path: string }[];
  };
  if (manifest.version !== 1 || !Array.isArray(manifest.migrations)) throw new Error('Invalid migration manifest');
  database.exec('CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, checksum TEXT NOT NULL, position INTEGER NOT NULL UNIQUE)');
  const applied = database.prepare('SELECT id, checksum, position FROM schema_migrations ORDER BY position').all() as { id: string; checksum: string; position: number }[];
  if (applied.length > manifest.migrations.length) throw new Error('Applied migration missing from manifest');
  const ids = new Set<string>();
  for (const [position, entry] of manifest.migrations.entries()) {
    if (!entry || !/^[a-z0-9-]{1,80}$/.test(entry.id) || typeof entry.path !== 'string' || ids.has(entry.id)) throw new Error('Invalid or duplicate migration ID');
    ids.add(entry.id);
    const path = resolve(root, entry.path);
    const rel = relative(root, path);
    if (isAbsolute(entry.path) || rel.startsWith('..') || !/^(core|reports)\/[^/]+\.sql$/.test(entry.path)) throw new Error('Migration path outside approved streams');
    const sql = readFileSync(path, 'utf8');
    const checksum = createHash('sha256').update(sql).digest('hex');
    const prior = applied[position];
    if (prior) {
      if (prior.id !== entry.id || prior.position !== position || prior.checksum !== checksum) throw new Error('Applied migration changed or reordered');
      continue;
    }
    database.transaction(() => {
      database.exec(sql);
      database.prepare('INSERT INTO schema_migrations(id, checksum, position) VALUES (?, ?, ?)').run(entry.id, checksum, position);
    })();
  }
}
