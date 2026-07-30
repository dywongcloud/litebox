import { migrate } from 'drizzle-orm/better-sqlite3/migrator';
import { eq } from 'drizzle-orm';

import { env } from '@/lib/env';
import { hashPassword } from '@/lib/security/crypto';
import { check as checkPassword } from '@/lib/auth/password-policy';

import { db } from './client';
import { applySeedCorpus } from './seed-corpus';
import { users } from './schema';

/**
 * First-run bootstrap: migrate, load the initial corpus, and create the
 * administrator account from `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD`.
 *
 * Safe to re-run: migrations are idempotent, the corpus load replaces the
 * business tables wholesale (see `applySeedCorpus`), and the admin step is
 * skipped once an account with that email already exists rather than failing
 * or resetting its password out from under someone.
 */
async function main(): Promise<void> {
  migrate(db, { migrationsFolder: './drizzle' });
  console.log('[seed] migrations applied');

  const counts = applySeedCorpus();
  console.log(
    `[seed] corpus loaded: ${counts.products} products, ${counts.accounts} accounts, ${counts.todos} todos`,
  );

  const email = env.BOOTSTRAP_ADMIN_EMAIL;
  const password = env.BOOTSTRAP_ADMIN_PASSWORD;

  if (!email || !password) {
    console.warn(
      '[seed] BOOTSTRAP_ADMIN_EMAIL / BOOTSTRAP_ADMIN_PASSWORD not set -- no admin account created. ' +
        'Set both in .env.local and re-run `npm run db:seed` to create one.',
    );
    return;
  }

  const existing = db.select().from(users).where(eq(users.email, email)).get();
  if (existing) {
    console.log(`[seed] admin account for ${email} already exists, leaving it unchanged`);
    return;
  }

  const policy = checkPassword(password);
  if (!policy.ok) {
    console.error('[seed] BOOTSTRAP_ADMIN_PASSWORD does not meet the password policy:');
    for (const problem of policy.problems) console.error(`  - ${problem}`);
    process.exitCode = 1;
    return;
  }

  const passwordHash = await hashPassword(password);
  db.insert(users)
    .values({
      email,
      displayName: 'Administrator',
      passwordHash,
      role: 'admin',
      locale: 'en',
      isActive: true,
    })
    .run();

  console.log(`[seed] created admin account for ${email}`);
}

main().catch((error: unknown) => {
  console.error('[seed] failed:', error);
  process.exitCode = 1;
});
