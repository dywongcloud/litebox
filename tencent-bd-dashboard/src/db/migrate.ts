import { migrate } from 'drizzle-orm/better-sqlite3/migrator';

import { db } from './client';

/**
 * Apply every migration under `drizzle/` that has not yet run.
 *
 * Idempotent: drizzle records applied migrations in its own bookkeeping table,
 * so running this on an already-current database is a no-op. Safe to call at
 * process start as well as from `npm run db:migrate`.
 */
migrate(db, { migrationsFolder: './drizzle' });
console.log('Migrations applied.');
