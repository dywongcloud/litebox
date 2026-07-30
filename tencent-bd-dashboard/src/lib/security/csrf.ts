import 'server-only';

import { cookies } from 'next/headers';

import { isProd } from '@/lib/env';

import { randomToken, safeEqual, signCsrf } from './crypto';
import { CSRF_FIELD } from './csrf-constants';

export { CSRF_FIELD };

/**
 * Signed double-submit CSRF tokens.
 *
 * The token is `<nonce>.<HMAC(sessionId, nonce)>`. It is placed in a readable
 * cookie and echoed back in the form body; both must be present, must match
 * each other, and the HMAC must verify against the *current* session id.
 *
 * Binding to the session id is what makes this stronger than a plain
 * double-submit: an attacker who can set a cookie on the victim's browser (via
 * a compromised sibling subdomain, say) still cannot mint a token that verifies
 * against the victim's session, because the HMAC key never leaves the server.
 *
 * This runs alongside the `Origin` check in `request.ts` -- neither is relied on
 * alone.
 */

export const CSRF_COOKIE = '__Host-bd_csrf';

/** `__Host-` requires Secure, so plain-HTTP development uses a bare name. */
export const csrfCookieName = isProd ? CSRF_COOKIE : 'bd_csrf';

/**
 * Deliberately readable by JavaScript, unlike the session cookie: the client
 * has to be able to copy it into a form field. It carries no authority on its
 * own -- possession without the session cookie proves nothing.
 */
function cookieOptions() {
  return {
    httpOnly: false,
    secure: isProd,
    sameSite: 'lax' as const,
    path: '/',
  };
}

/**
 * Mint a fresh CSRF token bound to `sessionId` and set its cookie.
 *
 * Writes a cookie, so this may only be called from a Server Action or Route
 * Handler -- Next.js forbids `cookies().set()` during an ordinary Server
 * Component render (a GET render must stay side-effect-free/cacheable). It is
 * called exactly once per session, from `session.create`/`session.rotate`,
 * both of which only ever run inside the `login`/`changePassword` Server
 * Actions.
 */
export async function issueForSession(sessionId: string): Promise<string> {
  const nonce = randomToken(16);
  const token = `${nonce}.${signCsrf(sessionId, nonce)}`;
  const store = await cookies();
  store.set(csrfCookieName, token, cookieOptions());
  return token;
}

/**
 * Read the current CSRF token for rendering into a hidden form field.
 *
 * Deliberately read-only: safe to call from any Server Component, including
 * page and layout renders, because it never touches the cookie jar. A session
 * created via `session.create` always has a matching token already set, so
 * the empty-string fallback is a defensive last resort, not the normal path --
 * a form rendered with it simply fails `verify` on submission (see
 * `requireMutation`), surfacing as "please reload and retry" rather than a
 * server error.
 */
export async function readToken(sessionId: string): Promise<string> {
  const store = await cookies();
  const existing = store.get(csrfCookieName)?.value;
  return existing && verifyShape(existing, sessionId) ? existing : '';
}

/** Check a token's structure and signature against a session id. */
function verifyShape(token: string, sessionId: string): boolean {
  const separator = token.indexOf('.');
  if (separator <= 0) return false;

  const nonce = token.slice(0, separator);
  const signature = token.slice(separator + 1);
  if (!nonce || !signature) return false;

  return safeEqual(signature, signCsrf(sessionId, nonce));
}

/**
 * Validate a submitted token.
 *
 * Requires all three of: a cookie, a matching submitted value, and a signature
 * valid for this session. Any missing piece is a rejection.
 */
export async function verify(submitted: string | null, sessionId: string): Promise<boolean> {
  if (!submitted) return false;

  const store = await cookies();
  const cookieValue = store.get(csrfCookieName)?.value;
  if (!cookieValue) return false;

  if (!safeEqual(cookieValue, submitted)) return false;

  return verifyShape(submitted, sessionId);
}

/** Drop the token, e.g. on sign-out so the next session mints a fresh one. */
export async function clear(): Promise<void> {
  const store = await cookies();
  store.set(csrfCookieName, '', { ...cookieOptions(), maxAge: 0 });
}
