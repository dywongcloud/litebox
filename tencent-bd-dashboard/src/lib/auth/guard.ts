import 'server-only';

import type { User } from '@/db/schema';
import * as audit from '@/lib/security/audit';
import { CSRF_FIELD, verify as verifyCsrf } from '@/lib/security/csrf';
import * as rateLimit from '@/lib/security/rate-limit';
import { context, isSameOrigin } from '@/lib/security/request';

import * as session from './session';
import { ForbiddenError, can, type Permission } from './rbac';

/**
 * The gate every Server Action passes through.
 *
 * Concentrating authentication, origin validation, CSRF verification, rate
 * limiting and authorisation into one call means a new action cannot
 * accidentally ship with one of them missing -- the only way to reach a mutation
 * helper is to have already produced an `AuthorizedActor`, and the only way to
 * produce one is `requireMutation`.
 *
 * The checks run in a deliberate order: cheap and unauthenticated first
 * (origin), then identity, then per-user cost (rate limit), then authorisation.
 * An unauthenticated flood is rejected before it can touch the password hasher
 * or the permission table.
 */

export class UnauthenticatedError extends Error {
  constructor(message = 'Authentication required') {
    super(message);
    this.name = 'UnauthenticatedError';
  }
}

export class CsrfError extends Error {
  constructor(message = 'Request failed origin or token validation') {
    super(message);
    this.name = 'CsrfError';
  }
}

export class RateLimitedError extends Error {
  readonly resetAt: number;

  constructor(resetAt: number) {
    super('Too many requests');
    this.name = 'RateLimitedError';
    this.resetAt = resetAt;
  }
}

export interface AuthorizedActor {
  readonly user: User;
  readonly sessionId: string;
  readonly ip: string;
  readonly userAgent: string;
}

/**
 * Read-side guard: authentication plus a permission, no CSRF or rate limit.
 *
 * Safe for page renders and GET handlers, which are not state-changing.
 */
export async function requireRead(permission: Permission): Promise<AuthorizedActor> {
  const active = await session.current();
  if (!active) throw new UnauthenticatedError();

  if (!can(active.user.role, permission)) {
    audit.record({
      action: 'auth.session.rejected',
      actorUserId: active.user.id,
      actorEmail: active.user.email,
      metadata: { permission, reason: 'forbidden' },
      outcome: 'failure',
    });
    throw new ForbiddenError(permission);
  }

  const ctx = await context();
  return {
    user: active.user,
    sessionId: active.sessionId,
    ip: ctx.ip,
    userAgent: ctx.userAgent,
  };
}

/**
 * Write-side guard. Everything `requireRead` does, plus the three protections
 * that only matter for state-changing requests.
 *
 * `formData` is the action's own payload; the CSRF token is read from it rather
 * than passed separately so a caller cannot forget to forward it.
 */
export async function requireMutation(
  permission: Permission,
  formData: FormData | null,
  options: { bucket?: rateLimit.RateLimitBucket } = {},
): Promise<AuthorizedActor> {
  // 1. Origin. Cheapest check, and the one that stops classic cross-site POSTs
  //    before any database work happens.
  if (!(await isSameOrigin())) {
    audit.record({
      action: 'auth.session.rejected',
      metadata: { permission, reason: 'cross-origin' },
      outcome: 'failure',
    });
    throw new CsrfError('Cross-origin request rejected');
  }

  // 2. Identity.
  const active = await session.current();
  if (!active) throw new UnauthenticatedError();

  // 3. CSRF token, bound to this specific session.
  const submitted = formData?.get(CSRF_FIELD);
  const token = typeof submitted === 'string' ? submitted : null;
  if (!(await verifyCsrf(token, active.sessionId))) {
    audit.record({
      action: 'auth.session.rejected',
      actorUserId: active.user.id,
      actorEmail: active.user.email,
      metadata: { permission, reason: 'csrf' },
      outcome: 'failure',
    });
    throw new CsrfError();
  }

  // 4. Rate limit, keyed on the session so one compromised account cannot
  //    exhaust the budget of every other user.
  const bucket = options.bucket ?? 'mutation';
  const limit = rateLimit.consume(bucket, active.sessionId);
  if (!limit.allowed) {
    audit.record({
      action: 'auth.session.rejected',
      actorUserId: active.user.id,
      actorEmail: active.user.email,
      metadata: { permission, reason: 'rate-limited', bucket },
      outcome: 'failure',
    });
    throw new RateLimitedError(limit.resetAt);
  }

  // 5. Authorisation.
  if (!can(active.user.role, permission)) {
    audit.record({
      action: 'auth.session.rejected',
      actorUserId: active.user.id,
      actorEmail: active.user.email,
      metadata: { permission, reason: 'forbidden' },
      outcome: 'failure',
    });
    throw new ForbiddenError(permission);
  }

  const ctx = await context();
  return {
    user: active.user,
    sessionId: active.sessionId,
    ip: ctx.ip,
    userAgent: ctx.userAgent,
  };
}

/** Current user without a permission requirement, or null. */
export async function optionalUser(): Promise<User | null> {
  const active = await session.current();
  return active?.user ?? null;
}

/**
 * Map a guard failure to a user-facing message.
 *
 * The messages are intentionally uninformative about *why* beyond the category:
 * a precise reason would help an attacker probe the boundary, and a real user
 * cannot act on the difference anyway.
 */
export function describeError(error: unknown): { message: string; status: number } {
  if (error instanceof UnauthenticatedError) {
    return { message: 'Your session has expired. Please sign in again.', status: 401 };
  }
  if (error instanceof ForbiddenError) {
    return { message: 'You do not have permission to perform this action.', status: 403 };
  }
  if (error instanceof CsrfError) {
    return { message: 'This request could not be verified. Please reload and retry.', status: 403 };
  }
  if (error instanceof RateLimitedError) {
    return { message: 'Too many requests. Please wait a moment and try again.', status: 429 };
  }
  return { message: 'Something went wrong. Please try again.', status: 500 };
}
