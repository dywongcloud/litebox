/**
 * The CSRF form field name, split out from `csrf.ts` so client components can
 * reference it without pulling in `next/headers` and the `server-only` guard
 * that module carries. Client components receive the token *value* as a plain
 * string prop from a server component parent; they only need this name to
 * label the hidden input consistently with what `requireMutation` reads.
 */
export const CSRF_FIELD = 'csrfToken';
