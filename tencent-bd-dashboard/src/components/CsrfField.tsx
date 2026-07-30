import * as session from '@/lib/auth/session';
import { CSRF_FIELD, readToken } from '@/lib/security/csrf';

/**
 * Hidden field carrying the current session's CSRF token.
 *
 * Every form that calls a mutating Server Action includes this; `requireMutation`
 * rejects the submission if it is missing or does not match. Server component
 * by necessity -- minting/reading the token needs the session cookie, which is
 * only available on the server.
 *
 * Renders nothing if there is no active session: at that point the containing
 * page is about to redirect to `/login` anyway, and a token bound to no
 * session would verify against nothing.
 */
export async function CsrfField() {
  const active = await session.current();
  if (!active) return null;

  const token = await readToken(active.sessionId);
  return <input type="hidden" name={CSRF_FIELD} value={token} />;
}
