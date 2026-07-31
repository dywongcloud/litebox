import 'server-only';

import { headers } from 'next/headers';

import { env, isProd } from '@/lib/env';

/**
 * Request-context helpers shared by the auth and CSRF layers.
 */

export interface RequestContext {
  readonly ip: string;
  readonly userAgent: string;
  readonly origin: string | null;
}

/**
 * Best-effort client IP.
 *
 * `x-forwarded-for` is client-controllable unless a trusted proxy overwrites
 * it, so this value is only ever used for rate limiting and pseudonymised audit
 * correlation -- never for an access decision. The left-most entry is taken
 * because that is the convention every mainstream proxy follows when appending.
 */
export async function clientIp(): Promise<string> {
  const h = await headers();

  const forwarded = h.get('x-forwarded-for');
  if (forwarded) {
    const first = forwarded.split(',')[0]?.trim();
    if (first) return first;
  }

  return h.get('x-real-ip')?.trim() ?? h.get('cf-connecting-ip')?.trim() ?? 'unknown';
}

export async function context(): Promise<RequestContext> {
  const h = await headers();
  return {
    ip: await clientIp(),
    userAgent: h.get('user-agent') ?? '',
    origin: h.get('origin'),
  };
}

/**
 * Origins accepted on a state-changing request.
 *
 * In production this is exactly `APP_ORIGIN`. In development localhost is
 * additionally allowed so the app is usable over plain HTTP without weakening
 * the deployed configuration.
 */
function allowedOrigins(): string[] {
  const configured = env.APP_ORIGIN ? [new URL(env.APP_ORIGIN).origin] : [];
  if (isProd) return configured;
  return [...configured, 'http://localhost:3000', 'http://127.0.0.1:3000'];
}

/**
 * Same-origin check for mutations.
 *
 * This is the primary CSRF defence: a cross-site form POST cannot forge the
 * `Origin` header, and browsers attach it to every non-GET request. The token
 * check in `csrf.ts` layers on top for defence in depth and for the case where
 * a legacy client omits the header.
 *
 * A missing `Origin` on a mutation is treated as a failure rather than waved
 * through -- being permissive here would reopen exactly the hole this closes.
 */
export async function isSameOrigin(): Promise<boolean> {
  const h = await headers();
  const permitted = allowedOrigins();

  const origin = h.get('origin');
  if (origin) {
    try {
      return permitted.includes(new URL(origin).origin);
    } catch {
      return false;
    }
  }

  // Some clients send only `Referer`. Accept it as a fallback signal, applying
  // the same allowlist.
  const referer = h.get('referer');
  if (referer) {
    try {
      return permitted.includes(new URL(referer).origin);
    } catch {
      return false;
    }
  }

  return false;
}
