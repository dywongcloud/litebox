/**
 * Root-level 404, outside the `[locale]` segment.
 *
 * Covers a request that never resolves to a locale at all -- there is no
 * locale context this deep (no `NextIntlClientProvider`, no design tokens
 * necessarily loaded), so this is deliberately self-contained rather than
 * reaching for translations or the app's CSS classes. In practice `src/proxy.ts`
 * and next-intl's own middleware intercept almost everything before it gets
 * here (see the redirect-to-login and redirect-to-default-locale paths); this
 * exists for the residual case that reaches neither -- a styled response
 * instead of Next's unstyled default.
 */
import Link from 'next/link';

export default function RootNotFound() {
  return (
    <html lang="en">
      <body style={{ margin: 0, fontFamily: 'system-ui, sans-serif', background: '#0a0d15', color: '#fff' }}>
        <div
          style={{
            minHeight: '100dvh',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 12,
            padding: 20,
            textAlign: 'center',
          }}
        >
          <h1 style={{ margin: 0, fontSize: 22 }}>Page not found</h1>
          <p style={{ margin: 0, color: '#9aa4b2', maxWidth: 420 }}>
            The page you asked for does not exist.
          </p>
          <Link href="/" style={{ color: '#4a85ff', marginTop: 8 }}>
            Go to the dashboard
          </Link>
        </div>
      </body>
    </html>
  );
}
