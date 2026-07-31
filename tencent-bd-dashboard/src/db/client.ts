import 'server-only';

import { mkdirSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';

import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';

import { env } from '@/lib/env';

import * as schema from './schema';

/**
 * Process-wide SQLite handle.
 *
 * Cached on `globalThis` because Next.js re-evaluates modules on every hot
 * reload in development; without the cache each edit would open another handle
 * and the WAL lock would eventually be exhausted.
 */
declare global {
  var __bdOsDatabase: Database.Database | undefined;
}

function openDatabase(): Database.Database {
  // The turbopackIgnore comment stops the build's file tracer from treating
  // this runtime-computed path as "could resolve to anything under the
  // project" and conservatively bundling the whole repo as a dependency of
  // the server output; the value is fully known at request time regardless.
  const path = isAbsolute(env.DATABASE_PATH)
    ? env.DATABASE_PATH
    : resolve(/* turbopackIgnore: true */ process.cwd(), env.DATABASE_PATH);

  mkdirSync(dirname(path), { recursive: true });

  const connection = new Database(path);

  // Must be the FIRST pragma set on the connection, before anything that can
  // itself contend for the database lock (journal_mode above all). `next
  // build` spawns several worker processes that each import this module and
  // open the same fresh database file concurrently -- the very first WAL
  // conversion below is exactly the kind of write that can hit SQLITE_BUSY
  // while another worker is mid-initialisation. Setting the busy timeout
  // first makes better-sqlite3 retry internally for up to 5s instead of
  // throwing immediately; setting it after `journal_mode = WAL` (as a
  // one-shot connection-local setting has no lock to wait on) does nothing
  // for the call that actually needs it.
  connection.pragma('busy_timeout = 5000');

  // WAL lets readers proceed during a write, which matters because every page
  // render reads while server actions write.
  connection.pragma('journal_mode = WAL');

  // Durable enough for this workload without an fsync on every commit.
  connection.pragma('synchronous = NORMAL');

  // Off by default in SQLite. The schema leans on ON DELETE CASCADE to keep
  // evidence, research and sessions from outliving their parent rows.
  connection.pragma('foreign_keys = ON');

  // Reject a write that would silently truncate an oversized value.
  connection.pragma('trusted_schema = OFF');

  // SQLite's defaults here are tuned for a constrained embedded device, not a
  // server process: a 2MB page cache and mmap I/O off. 64MB of cache and a
  // 256MB memory-mapped window cost nothing on a server and pay for
  // themselves on every read-heavy tab (the product catalog alone is 181+
  // rows re-scanned on most filter changes).
  connection.pragma('cache_size = -64000');
  connection.pragma('mmap_size = 268435456');

  return connection;
}

// Cached unconditionally, not just in development: Turbopack can duplicate a
// module across multiple output chunks that are all evaluated within the same
// running process, and each evaluation of this file must resolve to the exact
// same open handle -- two live `Database` connections to one WAL-mode file in
// one process is itself a source of the lock contention this module exists to
// avoid, not merely a development-mode hot-reload concern.
export const sqlite: Database.Database = globalThis.__bdOsDatabase ?? openDatabase();
globalThis.__bdOsDatabase = sqlite;

/**
 * Drizzle handle. Every query in the application goes through this: it is the
 * only place SQL is generated, and it always parameterises values, so no user
 * input is ever concatenated into a statement.
 */
export const db = drizzle(sqlite, { schema });

export type Db = typeof db;
export { schema };
