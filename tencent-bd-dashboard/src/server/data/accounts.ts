import 'server-only';

import { and, asc, eq, like, or, sql } from 'drizzle-orm';

import { db } from '@/db/client';
import { accountResearch, accounts } from '@/db/schema';
import type { Account, AccountResearch, NewAccount, NewAccountResearch } from '@/db/schema';
import type { AccountFilter } from '@/domain/schemas';

const PAGE_SIZE = 40;

export interface AccountListResult {
  readonly items: Account[];
  readonly total: number;
  readonly page: number;
  readonly pageSize: number;
}

export function listAccounts(filter: AccountFilter): AccountListResult {
  const clauses = [];

  if (filter.q) {
    const needle = `%${filter.q.toLowerCase()}%`;
    clauses.push(
      or(
        like(sql`lower(${accounts.company})`, needle),
        like(sql`lower(${accounts.industry})`, needle),
        like(sql`lower(${accounts.contact})`, needle),
        like(sql`lower(${accounts.pain})`, needle),
      ),
    );
  }
  if (filter.stage) clauses.push(eq(accounts.stage, filter.stage));

  const where = clauses.length > 0 ? and(...clauses) : undefined;
  const offset = (filter.page - 1) * PAGE_SIZE;

  const items = db
    .select()
    .from(accounts)
    .where(where)
    .orderBy(asc(accounts.company))
    .limit(PAGE_SIZE)
    .offset(offset)
    .all();

  const countRow = db.select({ count: sql<number>`count(*)` }).from(accounts).where(where).get();

  return { items, total: countRow?.count ?? 0, page: filter.page, pageSize: PAGE_SIZE };
}

export function getAccount(id: number): Account | undefined {
  return db.select().from(accounts).where(eq(accounts.id, id)).get();
}

export function getAccountResearch(accountId: number): AccountResearch | undefined {
  return db.select().from(accountResearch).where(eq(accountResearch.accountId, accountId)).get();
}

export function createAccount(values: NewAccount): Account {
  // `immediate`: grabs the write lock up front rather than lazily on the
  // first write, avoiding a deferred-transaction lock-upgrade deadlock under
  // concurrent writers (see the fuller note in `catalog/sync.ts`).
  return db.transaction(() => {
    const account = db.insert(accounts).values(values).returning().get();
    db.insert(accountResearch).values({ accountId: account.id }).run();
    return account;
  }, { behavior: 'immediate' });
}

export function updateAccount(id: number, values: Partial<NewAccount>): Account | undefined {
  return db
    .update(accounts)
    .set({ ...values, updatedAt: new Date() })
    .where(eq(accounts.id, id))
    .returning()
    .get();
}

export function deleteAccount(id: number): boolean {
  const result = db.delete(accounts).where(eq(accounts.id, id)).run();
  return result.changes > 0;
}

export function saveAccountResearch(
  accountId: number,
  values: Partial<NewAccountResearch>,
): AccountResearch {
  db.transaction(() => {
    const existing = getAccountResearch(accountId);
    if (existing) {
      db.update(accountResearch)
        .set({ ...values, updatedAt: new Date() })
        .where(eq(accountResearch.accountId, accountId))
        .run();
    } else {
      db.insert(accountResearch).values({ accountId, ...values }).run();
    }

    // Touch the parent row so "last updated" on the pipeline table reflects
    // research edits too, not only pipeline-field edits.
    db.update(accounts).set({ updatedAt: new Date() }).where(eq(accounts.id, accountId)).run();
  }, { behavior: 'immediate' });

  const result = getAccountResearch(accountId);
  if (!result) throw new Error('Account research row missing after save');
  return result;
}

export function countByStage(): Record<string, number> {
  const rows = db
    .select({ stage: accounts.stage, count: sql<number>`count(*)` })
    .from(accounts)
    .groupBy(accounts.stage)
    .all();

  return Object.fromEntries(rows.map((r) => [r.stage, r.count]));
}
