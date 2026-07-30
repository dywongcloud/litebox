import createIntlMiddleware from 'next-intl/middleware';
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

import { LOCALES } from '@/domain/enums';
import { routing } from '@/i18n/routing';

/**
 * Edge middleware: locale routing, a per-request CSP nonce, and the response
 * security headers.
 *
 * This layer deliberately does *not* authenticate. It runs on the Edge runtime
 * where the SQLite handle does not exist, so it can only see whether a session
 * cookie is present -- not whether it is valid, unexpired, or unrevoked. Acting
 * on cookie presence alone would be an authentication bypass waiting to happen.
 * The redirect below is a UX shortcut; every protected route independently
 * re-checks the session server-side through `requireRead`/`requireMutation`,
 * and that check is the only one that grants access.
 */

const intlMiddleware = createIntlMiddleware(routing);

/** Paths reachable without a session, matched after the locale prefix. */
const PUBLIC_PATHS = new Set(['/login']);

const SESSION_COOKIES = ['__Host-bd_session', 'bd_session'];

/**
 * Base64 nonce from the Edge runtime's Web Crypto.
 * 16 bytes is the CSP specification's recommended minimum.
 */
function createNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

function contentSecurityPolicy(nonce: string, isProduction: boolean): string {
  const directives = [
    // Nothing loads from anywhere unless a directive below widens it.
    `default-src 'self'`,

    // `strict-dynamic` lets the nonced Next.js bootstrap load its own chunks
    // without every chunk URL needing to be enumerated, while still refusing
    // any script an injected tag might introduce.
    //
    // `unsafe-eval` is required by the development bundler's HMR client only.
    isProduction
      ? `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`
      : `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval'`,

    // No nonce on style-src: a nonce would cause CSP3 browsers to ignore
    // `unsafe-inline`, and the framework emits un-nonced inline styles. This is
    // a narrow concession -- the app renders no user-supplied HTML, so there is
    // no injection point for a style-based attack to reach.
    `style-src 'self' 'unsafe-inline'`,

    `img-src 'self' data: blob:`,
    `font-src 'self' data:`,

    // Same-origin only. The Tencent Cloud APIs are called server-side, so the
    // browser never needs to reach a third-party host; anything trying to is
    // exfiltration.
    `connect-src 'self'`,

    `object-src 'none'`,
    `base-uri 'none'`,
    `form-action 'self'`,
    `frame-ancestors 'none'`,
    `frame-src 'none'`,
    `worker-src 'self' blob:`,
    `manifest-src 'self'`,
  ];

  if (isProduction) {
    directives.push('upgrade-insecure-requests');
  }

  return directives.join('; ');
}

function applySecurityHeaders(
  response: NextResponse,
  nonce: string,
  isProduction: boolean,
): NextResponse {
  const headers = response.headers;

  headers.set('Content-Security-Policy', contentSecurityPolicy(nonce, isProduction));

  // Stop the browser from second-guessing a declared Content-Type, which is how
  // a JSON export gets reinterpreted as HTML and executed.
  headers.set('X-Content-Type-Options', 'nosniff');

  // `frame-ancestors` above is the real control; this covers browsers that
  // still honour only the legacy header.
  headers.set('X-Frame-Options', 'DENY');

  // Send the origin but never the path to third parties: pipeline URLs contain
  // account identifiers.
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Deny every powerful feature. The dashboard needs none of them, so the
  // allowlist is empty rather than selective.
  headers.set(
    'Permissions-Policy',
    [
      'accelerometer=()',
      'camera=()',
      'display-capture=()',
      'geolocation=()',
      'gyroscope=()',
      'magnetometer=()',
      'microphone=()',
      'payment=()',
      'usb=()',
      'interest-cohort=()',
    ].join(', '),
  );

  // Process isolation: severs the window reference an opener could otherwise
  // use, and blocks cross-origin embedding of any resource this app serves.
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Resource-Policy', 'same-origin');

  if (isProduction) {
    headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }

  return response;
}

export default function middleware(request: NextRequest): NextResponse {
  const isProduction = process.env.NODE_ENV === 'production';
  const nonce = createNonce();

  // Forward the nonce to the render so the root layout can stamp it onto the
  // framework's script tags; without this they would be blocked by our own CSP.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('content-security-policy', contentSecurityPolicy(nonce, isProduction));

  const { pathname } = request.nextUrl;

  // Strip the locale prefix before deciding whether the route is public.
  const segments = pathname.split('/').filter(Boolean);
  const first = segments[0];
  const hasLocalePrefix = first !== undefined && (LOCALES as readonly string[]).includes(first);
  const pathWithoutLocale = hasLocalePrefix ? `/${segments.slice(1).join('/')}` : pathname;
  const normalised = pathWithoutLocale === '/' ? '/' : pathWithoutLocale.replace(/\/$/, '');

  const isPublic = PUBLIC_PATHS.has(normalised);
  const hasSessionCookie = SESSION_COOKIES.some((name) => request.cookies.has(name));

  // Unauthenticated visitor on a protected route: send them to sign in and
  // remember where they were headed. Purely a redirect -- see the note above.
  if (!isPublic && !hasSessionCookie) {
    const locale = hasLocalePrefix ? first : routing.defaultLocale;
    const url = request.nextUrl.clone();
    url.pathname = `/${locale}/login`;

    // Only a same-site path is ever echoed back, so this cannot be turned into
    // an open redirect.
    if (normalised !== '/') {
      url.searchParams.set('next', pathname);
    }

    return applySecurityHeaders(NextResponse.redirect(url), nonce, isProduction);
  }

  const intlResponse = intlMiddleware(request);

  // A redirect or rewrite is next-intl's decision about *where* the request
  // goes; pass it through untouched. No render happens on a redirect, so the
  // nonce has nowhere to be needed.
  const isRedirect = intlResponse.status >= 300 && intlResponse.status < 400;
  const isRewrite = intlResponse.headers.has('x-middleware-rewrite');

  if (isRedirect || isRewrite) {
    return applySecurityHeaders(intlResponse, nonce, isProduction);
  }

  // Pass-through case -- the common one, since `localePrefix: 'always'` means a
  // prefixed URL already matches the `[locale]` segment. Rebuild the response
  // so Next.js applies the overridden request headers to the render, which is
  // the only supported way to get the nonce into the root layout.
  const response = NextResponse.next({ request: { headers: requestHeaders } });

  // Carry over what next-intl decided: the locale cookie, and any Vary or
  // Link headers it emitted for content negotiation.
  for (const cookie of intlResponse.cookies.getAll()) {
    response.cookies.set(cookie);
  }
  for (const header of ['vary', 'link', 'x-middleware-set-cookie'] as const) {
    const value = intlResponse.headers.get(header);
    if (value) response.headers.set(header, value);
  }

  return applySecurityHeaders(response, nonce, isProduction);
}

export const config = {
  /**
   * Run on everything except static assets and the framework's own routes.
   * Matching those would add per-file overhead without adding protection --
   * they carry no session and change no state.
   */
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico|robots.txt|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)'],
};
