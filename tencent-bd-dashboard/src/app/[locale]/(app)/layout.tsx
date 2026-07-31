import { getTranslations } from 'next-intl/server';
import { redirect } from 'next/navigation';

import { permissionsFor } from '@/lib/auth/rbac';
import * as session from '@/lib/auth/session';
import { LocaleSwitcher } from '@/components/LocaleSwitcher';
import { NavTabs } from '@/components/NavTabs';
import { SignOutForm } from '@/components/SignOutForm';

/**
 * Chrome for every authenticated dashboard route: header, tab strip, and the
 * `<main>` content wrapper.
 *
 * This is a second, independent authentication check on top of the redirect
 * middleware already performs -- see the note in `src/middleware.ts` on why
 * the Edge layer cannot itself validate a session. This is the check that
 * actually grants or denies the page.
 */
export default async function AppLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  const active = await session.current();

  if (!active) {
    redirect(`/${locale}/login`);
  }

  const t = await getTranslations('app');
  const permissions = permissionsFor(active.user.role);

  return (
    <>
      <header className="app-header">
        <div className="app-header-row">
          <div>
            <h1>{t('title')}</h1>
            <div className="sub">{t('subtitle')}</div>
          </div>
          <div className="app-actions">
            <span className="small" style={{ color: '#b9c7db' }}>
              {t('signedInAs', { name: active.user.displayName || active.user.email })}
              {' · '}
              {t('role')}: {active.user.role}
            </span>
            <LocaleSwitcher />
            <SignOutForm />
          </div>
        </div>
      </header>

      <NavTabs grantedPermissions={permissions} isAdmin={active.user.role === 'admin'} />

      <main className="app-main">{children}</main>
    </>
  );
}
