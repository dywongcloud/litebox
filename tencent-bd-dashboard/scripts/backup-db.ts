/**
 * Hot backup of the live SQLite database, safe to run while the app is
 * serving traffic.
 *
 * Two steps, in this order:
 *  1. `PRAGMA wal_checkpoint(TRUNCATE)` folds the write-ahead log back into
 *     the main database file and truncates it to empty. WAL mode auto-
 *     checkpoints on its own, but only opportunistically (every ~1000 pages,
 *     and never while a read holds the WAL open) -- a long-lived reporting
 *     query or a burst of writes between backups can otherwise leave the WAL
 *     file large indefinitely, since nothing else in this app ever forces one.
 *  2. better-sqlite3's `.backup()`, which is SQLite's Online Backup API: it
 *     copies the database page-by-page under a read lock, safe to run
 *     concurrently with writers, unlike copying the `.db` file with `cp`
 *     (which can copy a torn, mid-write set of pages).
 *
 * Run: npm run db:backup [destination-path]
 * Defaults to `backups/bd-os-<timestamp>.db` next to the project root.
 */

import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

async function main(): Promise<void> {
  const { sqlite } = await import('../src/db/client');

  const explicit = process.argv[2];
  const destination = explicit
    ? resolve(process.cwd(), explicit)
    : join(process.cwd(), 'backups', `bd-os-${new Date().toISOString().replace(/[:.]/g, '-')}.db`);

  mkdirSync(dirname(destination), { recursive: true });

  if (existsSync(destination)) {
    throw new Error(`Refusing to overwrite existing file: ${destination}`);
  }

  const checkpoint = sqlite.pragma('wal_checkpoint(TRUNCATE)') as Array<{
    busy: number;
    log: number;
    checkpointed: number;
  }>;
  const result = checkpoint[0];
  if (result?.busy) {
    console.warn('[backup] checkpoint could not fully complete (a writer or reader held the WAL open); continuing anyway.');
  }
  console.log(`[backup] checkpointed ${result?.checkpointed ?? 0}/${result?.log ?? 0} WAL frames`);

  await sqlite.backup(destination);
  console.log(`[backup] wrote ${destination}`);

  sqlite.close();
}

main().catch((error) => {
  console.error('[backup] failed:', error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
