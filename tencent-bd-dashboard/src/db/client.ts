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
  // eslint-disable-next-line no-var
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

  // WAL lets readers proceed during a write, which matters because every page
  // render reads while server actions write.
  connection.pragma('journal_mode = WAL');

  // Durable enough for this workload without an fsync on every commit.
  connection.pragma('synchronous = NORMAL');

  // Off by default in SQLite. The schema leans on ON DELETE CASCADE to keep
  // evidence, research and sessions from outliving their parent rows.
  connection.pragma('foreign_keys = ON');

  // Fail a contended write after 5s rather than throwing SQLITE_BUSY at once.
  connection.pragma('busy_timeout = 5000');

  // Reject a write that would silently truncate an oversized value.
  connection.pragma('trusted_schema = OFF');

  return connection;
}

export const sqlite: Database.Database = globalThis.__bdOsDatabase ?? openDatabase();

if (process.env.NODE_ENV !== 'production') {
  globalThis.__bdOsDatabase = sqlite;
}

/**
 * Drizzle handle. Every query in the application goes through this: it is the
 * only place SQL is generated, and it always parameterises values, so no user
 * input is ever concatenated into a statement.
 */
export const db = drizzle(sqlite, { schema });

export type Db = typeof db;
export { schema };
