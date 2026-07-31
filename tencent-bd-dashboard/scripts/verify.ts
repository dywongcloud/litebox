/**
 * Lightweight smoke test: migrate a throwaway database, load the seed
 * corpus, and assert a handful of invariants that would catch the most
 * likely regressions (a broken migration, a seed script that silently loads
 * zero rows, a password hash that does not round-trip).
 *
 * Deliberately not a test framework: this project has no `*.test.ts` files
 * and does not depend on one. This script exercises real code against a
 * real (temporary) SQLite database -- the same kind of check as running the
 * app itself, just scripted and assertion-based rather than clicked through
 * by hand.
 *
 * Run: npm run verify
 */

import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env.DATABASE_PATH = join(mkdtempSync(join(tmpdir(), 'bd-os-verify-')), 'verify.db');

async function main(): Promise<void> {
  const failures: string[] = [];
  const check = (label: string, ok: boolean) => {
    console.log(`${ok ? 'PASS' : 'FAIL'} - ${label}`);
    if (!ok) failures.push(label);
  };

  const { migrate } = await import('drizzle-orm/better-sqlite3/migrator');
  const { db, sqlite } = await import('../src/db/client');
  const { applySeedCorpus } = await import('../src/db/seed-corpus');
  const { products, accounts, todos, sopSteps, motions } = await import('../src/db/schema');
  const { hashPassword, verifyPassword } = await import('../src/lib/security/crypto');
  const { check: checkPasswordPolicy } = await import('../src/lib/auth/password-policy');
  const { productSchema, accountSchema } = await import('../src/domain/schemas');

  migrate(db, { migrationsFolder: join(__dirname, '..', 'drizzle') });
  check('migrations applied without throwing', true);

  const counts = applySeedCorpus();
  check(`seed loaded 181 products (got ${counts.products})`, counts.products === 181);
  check(`seed loaded at least 1 account (got ${counts.accounts})`, counts.accounts >= 1);

  const productRows = db.select().from(products).all();
  check('products table row count matches reported count', productRows.length === counts.products);
  check('every product has a non-empty name', productRows.every((p) => p.product.trim() !== ''));
  check(
    'every product has a valid priority (P1/P2/P3)',
    productRows.every((p) => ['P1', 'P2', 'P3'].includes(p.priority)),
  );

  const accountRows = db.select().from(accounts).all();
  check('accounts table has rows', accountRows.length > 0);

  const todoRows = db.select().from(todos).all();
  check('todos seeded', todoRows.length > 0);

  const sopRows = db.select().from(sopSteps).all();
  check('SOP checklist seeded', sopRows.length > 0);

  const motionRows = db.select().from(motions).all();
  check('sales motions seeded', motionRows.length === 10);

  // Password hashing round-trip.
  const password = 'Correct-Horse-Battery-Staple-9!';
  const hash = await hashPassword(password);
  check('scrypt hash verifies against its own password', await verifyPassword(password, hash));
  check('scrypt hash rejects a wrong password', !(await verifyPassword('wrong-password-entirely', hash)));
  check('password policy accepts a strong password', checkPasswordPolicy(password).ok);
  check('password policy rejects a common weak password', !checkPasswordPolicy('password123').ok);

  // Zod schemas reject malformed input at the same boundary the Server Actions use.
  const badProduct = productSchema.safeParse({ category: '', product: '', priority: 'P9' });
  check('productSchema rejects an empty name and invalid priority', !badProduct.success);

  const goodAccount = accountSchema.safeParse({
    company: 'Test Co',
    region: '',
    industry: '',
    size: 'Scale-up',
    incumbent: '',
    products: '',
    pain: '',
    trigger: '',
    contact: '',
    path: '',
    stage: 'Target',
    fit: 'Medium',
    nextAction: '',
    dueOn: '',
    notes: '',
  });
  check('accountSchema accepts a minimal valid account', goodAccount.success);

  sqlite.close();
  const dbPath = process.env.DATABASE_PATH!;
  if (existsSync(dbPath)) rmSync(join(dbPath, '..'), { recursive: true, force: true });

  if (failures.length > 0) {
    console.error(`\n${failures.length} check(s) failed:`);
    for (const f of failures) console.error(`  - ${f}`);
    process.exitCode = 1;
    return;
  }

  console.log('\nAll checks passed.');
}

main().catch((error: unknown) => {
  console.error('verify script crashed:', error);
  process.exitCode = 1;
});
