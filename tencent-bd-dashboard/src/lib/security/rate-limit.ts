import 'server-only';

import { eq, lt, sql } from 'drizzle-orm';

import { db } from '@/db/client';
import { rateLimits } from '@/db/schema';

import { pseudonymise } from './crypto';

/**
 * Persisted fixed-window rate limiter.
 *
 * SQLite is already the source of truth and every request path touches it, so
 * counters live there rather than in module memory. That survives a restart and
 * holds across workers -- an in-process counter would let an attacker reset the
 * window by forcing a reload, or simply spread attempts across processes.
 *
 * Subjects are pseudonymised before they become part of a key, so the table
 * never stores a raw IP address or email.
 */

export type RateLimitBucket =
  | 'login'
  | 'login-ip'
  | 'mutation'
  | 'translate'
  | 'catalog-sync'
  | 'export';

interface BucketPolicy {
  readonly limit: number;
  readonly windowMs: number;
}

/**
 * Per-bucket policy. `login` is deliberately the tightest: it is the only
 * endpoint where a successful guess grants everything else.
 */
const POLICIES: Record<RateLimitBucket, BucketPolicy> = {
  login: { limit: 10, windowMs: 15 * 60_000 },
  'login-ip': { limit: 30, windowMs: 15 * 60_000 },
  mutation: { limit: 240, windowMs: 60_000 },
  translate: { limit: 60, windowMs: 60_000 },
  'catalog-sync': { limit: 4, windowMs: 60 * 60_000 },
  export: { limit: 12, windowMs: 60_000 },
};

export interface RateLimitResult {
  readonly allowed: boolean;
  readonly remaining: number;
  /** Epoch ms at which the current window ends. */
  readonly resetAt: number;
}

/**
 * Count one request against `bucket` for `subject`.
 *
 * The read-modify-write runs inside a synchronous better-sqlite3 transaction,
 * so two concurrent requests cannot both observe `count = limit - 1` and both
 * be allowed through.
 */
export function consume(bucket: RateLimitBucket, subject: string): RateLimitResult {
  const policy = POLICIES[bucket];
  const key = `${bucket}:${pseudonymise(subject)}`;
  const now = Date.now();

  return db.transaction((): RateLimitResult => {
    const existing = db.select().from(rateLimits).where(eq(rateLimits.key, key)).get();

    // No window, or the previous one has elapsed: start a fresh one.
    if (!existing || existing.expiresAt.getTime() <= now) {
      const expiresAt = new Date(now + policy.windowMs);
      db.insert(rateLimits)
        .values({
          key,
          count: 1,
          windowStartedAt: new Date(now),
          expiresAt,
        })
        .onConflictDoUpdate({
          target: rateLimits.key,
          set: { count: 1, windowStartedAt: new Date(now), expiresAt },
        })
        .run();

      return { allowed: true, remaining: policy.limit - 1, resetAt: expiresAt.getTime() };
    }

    const resetAt = existing.expiresAt.getTime();

    // Already over the limit: do not increment further, so a flood of blocked
    // requests cannot extend the window or overflow the counter.
    if (existing.count >= policy.limit) {
      return { allowed: false, remaining: 0, resetAt };
    }

    db.update(rateLimits)
      .set({ count: sql`${rateLimits.count} + 1` })
      .where(eq(rateLimits.key, key))
      .run();

    return {
      allowed: true,
      remaining: policy.limit - (existing.count + 1),
      resetAt,
    };
  });
}

/** Clear a subject's counter, e.g. after a successful sign-in. */
export function reset(bucket: RateLimitBucket, subject: string): void {
  db.delete(rateLimits)
    .where(eq(rateLimits.key, `${bucket}:${pseudonymise(subject)}`))
    .run();
}

/**
 * Inspect a bucket without counting against it, for pre-flight checks that
 * should not themselves consume budget.
 */
export function peek(bucket: RateLimitBucket, subject: string): RateLimitResult {
  const policy = POLICIES[bucket];
  const key = `${bucket}:${pseudonymise(subject)}`;
  const now = Date.now();

  const existing = db.select().from(rateLimits).where(eq(rateLimits.key, key)).get();
  if (!existing || existing.expiresAt.getTime() <= now) {
    return { allowed: true, remaining: policy.limit, resetAt: now + policy.windowMs };
  }

  return {
    allowed: existing.count < policy.limit,
    remaining: Math.max(0, policy.limit - existing.count),
    resetAt: existing.expiresAt.getTime(),
  };
}

/**
 * Drop elapsed windows. Called opportunistically from the session sweep rather
 * than on a timer, so there is no background job to keep alive.
 */
export function sweepExpired(): number {
  const result = db.delete(rateLimits).where(lt(rateLimits.expiresAt, new Date())).run();
  return result.changes;
}

/** Narrow helper used by the sign-in path, which limits on two axes at once. */
export function consumeAll(
  entries: ReadonlyArray<readonly [RateLimitBucket, string]>,
): RateLimitResult {
  let worst: RateLimitResult = { allowed: true, remaining: Number.MAX_SAFE_INTEGER, resetAt: 0 };

  for (const [bucket, subject] of entries) {
    const result = consume(bucket, subject);
    if (!result.allowed || result.remaining < worst.remaining) {
      worst = result;
    }
  }

  return worst;
}

/** Exported for the operator-facing settings page. */
export function policyFor(bucket: RateLimitBucket): BucketPolicy {
  return POLICIES[bucket];
}
