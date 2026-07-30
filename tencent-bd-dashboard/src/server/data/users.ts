import 'server-only';

import { asc, eq, sql } from 'drizzle-orm';

import { db } from '@/db/client';
import { users } from '@/db/schema';
import type { NewUser, User } from '@/db/schema';

export function findByEmail(email: string): User | undefined {
  return db.select().from(users).where(eq(users.email, email.trim().toLowerCase())).get();
}

export function getUser(id: number): User | undefined {
  return db.select().from(users).where(eq(users.id, id)).get();
}

export function listUsers(): User[] {
  return db.select().from(users).orderBy(asc(users.email)).all();
}

export function createUser(values: NewUser): User {
  return db.insert(users).values({ ...values, email: values.email.trim().toLowerCase() }).returning().get();
}

export function updateUser(id: number, values: Partial<NewUser>): User | undefined {
  return db
    .update(users)
    .set({ ...values, updatedAt: new Date() })
    .where(eq(users.id, id))
    .returning()
    .get();
}

export function recordLoginSuccess(id: number): void {
  db.update(users)
    .set({ failedLoginCount: 0, lockedUntil: null, lastLoginAt: new Date(), updatedAt: new Date() })
    .where(eq(users.id, id))
    .run();
}

/**
 * Record a failed attempt and lock the account once the threshold is reached.
 *
 * Runs as a single atomic update rather than read-then-write, so two failed
 * attempts racing each other cannot both read the same pre-increment count and
 * under-count the lockout.
 */
export function recordLoginFailure(
  id: number,
  maxAttempts: number,
  lockoutSeconds: number,
): { failedLoginCount: number; lockedUntil: Date | null } {
  const updated = db
    .update(users)
    .set({
      failedLoginCount: sql`${users.failedLoginCount} + 1`,
      lockedUntil: sql`case when ${users.failedLoginCount} + 1 >= ${maxAttempts}
        then ${Date.now() + lockoutSeconds * 1000}
        else ${users.lockedUntil} end`,
      updatedAt: new Date(),
    })
    .where(eq(users.id, id))
    .returning({ failedLoginCount: users.failedLoginCount, lockedUntil: users.lockedUntil })
    .get();

  return updated;
}

export function setPassword(id: number, passwordHash: string): void {
  db.update(users)
    .set({ passwordHash, failedLoginCount: 0, lockedUntil: null, updatedAt: new Date() })
    .where(eq(users.id, id))
    .run();
}
