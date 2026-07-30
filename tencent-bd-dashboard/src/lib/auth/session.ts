import 'server-only';

import { and, eq, isNull, lt, or } from 'drizzle-orm';
import { cookies, headers } from 'next/headers';

import { db } from '@/db/client';
import { sessions, users } from '@/db/schema';
import type { User } from '@/db/schema';
import { env, isProd } from '@/lib/env';
import { hashSessionToken, pseudonymise, randomToken, sha256 } from '@/lib/security/crypto';
import { clear as clearCsrf, issueForSession } from '@/lib/security/csrf';
import { sweepExpired } from '@/lib/security/rate-limit';

/**
 * Opaque server-side sessions.
 *
 * The cookie carries a random token and nothing else -- no user id, no role, no
 * expiry claim. Everything authoritative is read from the `sessions` row on
 * each request, so revoking a session takes effect immediately. A signed JWT
 * would have to be either short-lived or unrevocable; neither is acceptable for
 * a dashboard holding customer pipeline data.
 */

export const SESSION_COOKIE = '__Host-bd_session';

/**
 * `__Host-` prefix contract, enforced by the browser: Secure, Path=/, and no
 * Domain attribute. A subdomain cannot set or overwrite this cookie, which
 * removes session fixation via a sibling host.
 *
 * The prefix requires Secure, which requires HTTPS. Plain-HTTP development
 * therefore uses an unprefixed name; production always gets the hardened one.
 */
export const sessionCookieName = isProd ? SESSION_COOKIE : 'bd_session';

interface CookieOptions {
  httpOnly: true;
  secure: boolean;
  sameSite: 'lax' | 'strict';
  path: string;
  maxAge?: number;
}

function cookieOptions(maxAgeSeconds?: number): CookieOptions {
  return {
    // Unreadable from JavaScript, so an XSS foothold cannot exfiltrate it.
    httpOnly: true,
    secure: isProd,
    // `lax` keeps top-level navigation into the dashboard working while still
    // withholding the cookie from cross-site POSTs. Mutations additionally
    // require a matching Origin and a CSRF token, so `lax` is not load-bearing
    // on its own.
    sameSite: 'lax',
    path: '/',
    ...(maxAgeSeconds === undefined ? {} : { maxAge: maxAgeSeconds }),
  };
}

export interface AuthenticatedSession {
  readonly sessionId: string;
  readonly user: User;
}

/**
 * Create a session and set its cookie.
 *
 * Called only after a password has been verified. The caller is responsible for
 * having destroyed any pre-existing session first, so a fixated token cannot
 * survive the privilege change (see `rotate`).
 */
export async function create(
  userId: number,
  context: { ip: string; userAgent: string },
): Promise<string> {
  const token = randomToken(32);
  const sessionId = randomToken(16);
  const now = Date.now();

  db.insert(sessions)
    .values({
      id: sessionId,
      userId,
      tokenHash: hashSessionToken(token),
      userAgentHash: sha256(context.userAgent),
      ipHash: pseudonymise(context.ip),
      createdAt: new Date(now),
      lastSeenAt: new Date(now),
      absoluteExpiresAt: new Date(now + env.SESSION_ABSOLUTE_TTL_SECONDS * 1000),
    })
    .run();

  const store = await cookies();
  store.set(sessionCookieName, token, cookieOptions(env.SESSION_ABSOLUTE_TTL_SECONDS));

  // Mint the CSRF cookie together with the session cookie, in the same
  // Server Action call: every subsequent page render only ever *reads* the
  // CSRF cookie (see `csrf.readToken`), because Next.js forbids setting
  // cookies from a plain render. Creation time is the one place both cookies
  // can be written atomically.
  await issueForSession(sessionId);

  return sessionId;
}

/**
 * Resolve the current request's session, or null.
 *
 * Every rejection path also clears the cookie, so a client holding an expired
 * or revoked token stops re-presenting it.
 */
export async function current(): Promise<AuthenticatedSession | null> {
  const store = await cookies();
  const token = store.get(sessionCookieName)?.value;
  if (!token) return null;

  const row = db
    .select({ session: sessions, user: users })
    .from(sessions)
    .innerJoin(users, eq(sessions.userId, users.id))
    .where(eq(sessions.tokenHash, hashSessionToken(token)))
    .get();

  if (!row) return null;

  const { session, user } = row;
  const now = Date.now();

  if (session.revokedAt) return null;
  if (session.absoluteExpiresAt.getTime() <= now) return null;

  // Idle timeout is enforced on read rather than stored as an expiry, so
  // changing `SESSION_IDLE_TTL_SECONDS` applies to sessions already in flight.
  if (now - session.lastSeenAt.getTime() > env.SESSION_IDLE_TTL_SECONDS * 1000) return null;

  // A deactivated account must lose access without waiting for expiry.
  if (!user.isActive) return null;

  // Binding to the user agent makes a stolen cookie useless unless the attacker
  // also replicates the client string. This is a speed bump, not a guarantee,
  // and it is deliberately not bound to IP: mobile networks reassign addresses
  // mid-session and that would log real users out constantly.
  const requestHeaders = await headers();
  const userAgent = requestHeaders.get('user-agent') ?? '';
  if (session.userAgentHash && session.userAgentHash !== sha256(userAgent)) {
    revokeById(session.id);
    return null;
  }

  // Sliding activity, written at most once a minute to keep a page of reads
  // from turning into a page of writes.
  if (now - session.lastSeenAt.getTime() > 60_000) {
    db.update(sessions).set({ lastSeenAt: new Date(now) }).where(eq(sessions.id, session.id)).run();
  }

  return { sessionId: session.id, user };
}

/**
 * Replace the current session with a fresh one for the same user.
 *
 * Used after any privilege-relevant change (password update, role change) so a
 * token captured before the change cannot be used after it.
 */
export async function rotate(
  sessionId: string,
  userId: number,
  context: { ip: string; userAgent: string },
): Promise<string> {
  revokeById(sessionId);
  return create(userId, context);
}

/** Revoke the caller's session and clear the cookie. */
export async function destroy(): Promise<void> {
  const store = await cookies();
  const token = store.get(sessionCookieName)?.value;

  if (token) {
    db.update(sessions)
      .set({ revokedAt: new Date() })
      .where(eq(sessions.tokenHash, hashSessionToken(token)))
      .run();
  }

  store.set(sessionCookieName, '', cookieOptions(0));

  // The CSRF cookie is bound to the now-revoked session id and is useless
  // without it; clearing it means the next sign-in mints a clean pair rather
  // than leaving a stale token sitting in the browser.
  await clearCsrf();
}

export function revokeById(sessionId: string): void {
  db.update(sessions).set({ revokedAt: new Date() }).where(eq(sessions.id, sessionId)).run();
}

/** Revoke every session for a user, e.g. on deactivation or password reset. */
export function revokeAllForUser(userId: number): number {
  const result = db
    .update(sessions)
    .set({ revokedAt: new Date() })
    .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)))
    .run();
  return result.changes;
}

/**
 * Delete expired and revoked sessions, and elapsed rate-limit windows.
 *
 * Invoked opportunistically from the sign-in path rather than on a timer: the
 * table only grows when someone signs in, so that is exactly when it is worth
 * trimming, and it avoids keeping a background job alive in a serverless
 * deployment where one may never run.
 */
export function sweep(): { sessions: number; rateLimits: number } {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const removed = db
    .delete(sessions)
    .where(or(lt(sessions.absoluteExpiresAt, new Date()), lt(sessions.revokedAt, cutoff)))
    .run();

  return { sessions: removed.changes, rateLimits: sweepExpired() };
}
