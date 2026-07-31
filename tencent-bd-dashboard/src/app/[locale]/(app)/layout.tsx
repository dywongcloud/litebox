import { getTranslations } from 'next-intl/server';
import { redirect } from 'next/navigation';

import { permissionsFor } from '@/lib/auth/rbac';
import * as session from '@/lib/auth/session';
import { LocaleSwitcher } from '@/components/LocaleSwitcher';
import { NavTabs } from '@/components/NavTabs';
import { SignOutForm } from '@/components/SignOutForm';
import { ToastProvider } from '@/components/ui/toast';
import { TooltipProvider } from '@/components/ui/tooltip';

/**
 * Chrome for every authenticated dashboard route: header, tab strip, and the
 * `<main>` content wrapper.
 *
 * This is a second, independent authentication check on top of the redirect
 * `src/proxy.ts` already performs -- see the note there on why the Edge layer
 * cannot itself validate a session. This is the check that actually grants or
 * denies the page.
 *
 * `TooltipProvider` is hoisted to the layout rather than repeated per page so
 * every tooltip on a route shares one delay timer: Radix skips the open delay
 * for a second tooltip entered soon after a first, which is what makes
 * scanning across a row of truncated cells feel continuous instead of
 * stuttering through a fresh delay on each one.
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
    <ToastProvider>
      <TooltipProvider delayDuration={200} skipDelayDuration={400}>
        {/* Header and tab strip stick as one unit. Sticking them separately
            meant the strip needed a `top` offset equal to the header's
            rendered height -- a hardcoded pixel value that silently drifted
            whenever the header's type or padding changed, and differed by
            locale. Nesting removes the measurement entirely. */}
        <div className="app-chrome">
          <header className="app-header">
            <div className="app-header-row">
            <div className="app-brand">
              <span className="app-mark" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" width="18" height="18">
                  <path
                    d="M12 2.6 21 7.4v9.2L12 21.4 3 16.6V7.4z"
                    stroke="currentColor"
                    strokeWidth="1.7"
                    strokeLinejoin="round"
                  />
                  <path d="M12 11.2 21 7.4M12 11.2v10.2M12 11.2 3 7.4" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" opacity="0.65" />
                </svg>
              </span>
              <div>
                <h1>{t('title')}</h1>
                <div className="sub">{t('subtitle')}</div>
              </div>
            </div>
              <div className="app-actions">
                <span className="small app-user-info">
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
        </div>

        <main className="app-main">{children}</main>
      </TooltipProvider>
    </ToastProvider>
  );
}
