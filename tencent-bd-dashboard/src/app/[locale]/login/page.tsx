import { getTranslations } from 'next-intl/server';
import { redirect } from 'next/navigation';

import * as session from '@/lib/auth/session';

import { LoginForm } from './LoginForm';

/**
 * A signed-in visitor hitting `/login` (stale tab, back button after sign-in)
 * is bounced to the dashboard rather than shown the form again.
 */
export default async function LoginPage({
  params,
  searchParams,
}: {
  params: Promise<{ locale: string }>;
  searchParams: Promise<{ next?: string }>;
}) {
  const { locale } = await params;
  const { next } = await searchParams;

  const active = await session.current();
  if (active) redirect(`/${locale}/products`);

  const t = await getTranslations('auth');

  return (
    <div className="auth-shell">
      <div className="auth-card stack">
        <div>
          <h1 style={{ margin: '0 0 6px', fontSize: 20 }}>{t('signInTitle')}</h1>
          <p className="small">{t('signInSubtitle')}</p>
        </div>
        <LoginForm next={next && next.startsWith('/') && !next.startsWith('//') ? next : undefined} />
      </div>
    </div>
  );
}
