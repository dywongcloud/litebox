'use client';

import { useEffect, useState } from 'react';
import { useTranslations } from 'next-intl';

import { Link, usePathname } from '@/i18n/navigation';
import type { Permission } from '@/lib/auth/rbac';

const TABS = [
  { href: '/products', labelKey: 'nav.products', permission: 'catalog.read' },
  { href: '/accounts', labelKey: 'nav.accounts', permission: 'account.read' },
  { href: '/sop', labelKey: 'nav.sop', permission: 'playbook.read' },
  { href: '/board', labelKey: 'nav.board', permission: 'board.read' },
  { href: '/playbooks', labelKey: 'nav.playbooks', permission: 'playbook.read' },
  { href: '/weekly', labelKey: 'nav.weekly', permission: 'review.read' },
] as const;

/**
 * Client component so the active tab can react to client-side navigation
 * without a full server round trip; the permission check that decides what a
 * user may reach lives entirely server-side (in `requireRead`/`requireMutation`)
 * -- hiding a tab here is a convenience, never the access boundary.
 *
 * Renders two markup branches for the same data, toggled by CSS media query
 * (`.desktop-tabs` / `.mobile-nav`) rather than a JS viewport check: both are
 * in the initial server-rendered HTML, so there is no layout shift or
 * client-only flash while a resize listener spins up, and the correct one is
 * simply the one CSS chose to display before any JS runs.
 */
export function NavTabs({ grantedPermissions, isAdmin }: { grantedPermissions: readonly Permission[]; isAdmin: boolean }) {
  const t = useTranslations();
  const pathname = usePathname();
  const granted = new Set(grantedPermissions);
  const [open, setOpen] = useState(false);
  // Closing the panel on navigation is state derived from a prop (`pathname`)
  // changing, not a side effect on an external system -- doing it during
  // render (React's documented pattern for this exact case) avoids the extra
  // render pass a `useEffect` + `setState` round trip would cost.
  const [renderedForPathname, setRenderedForPathname] = useState(pathname);
  if (pathname !== renderedForPathname) {
    setRenderedForPathname(pathname);
    setOpen(false);
  }

  const items = TABS.filter((tab) => granted.has(tab.permission));
  const activeItem = [...items, isAdmin ? { href: '/admin' as const, labelKey: 'nav.admin' as const } : null]
    .filter(Boolean)
    .find((tab) => tab!.href === pathname);

  useEffect(() => {
    if (!open) return;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false);
    }
    document.addEventListener('keydown', onKeyDown);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = '';
    };
  }, [open]);

  return (
    <>
      <nav className="app-tabs desktop-tabs" aria-label="Primary">
        {items.map((tab) => (
          <Link key={tab.href} href={tab.href} className="app-tab" data-active={pathname === tab.href}>
            {t(tab.labelKey)}
          </Link>
        ))}
        {isAdmin ? (
          <Link href="/admin" className="app-tab" data-active={pathname === '/admin'}>
            {t('nav.admin')}
          </Link>
        ) : null}
      </nav>

      <div className="mobile-nav">
        <button type="button" className="mobile-nav-trigger" onClick={() => setOpen(true)} aria-expanded={open} aria-haspopup="true">
          <MenuIcon />
          <span>{activeItem ? t(activeItem.labelKey) : t('nav.products')}</span>
        </button>
      </div>

      {open ? (
        <div className="mobile-nav-overlay" role="presentation" onClick={() => setOpen(false)}>
          <div className="mobile-nav-panel" role="dialog" aria-modal="true" aria-label="Primary navigation" onClick={(e) => e.stopPropagation()}>
            <div className="spread" style={{ marginBottom: 'var(--space-4)' }}>
              <strong>{t('app.title')}</strong>
              <button type="button" onClick={() => setOpen(false)} aria-label="Close menu">
                <CloseIcon />
              </button>
            </div>
            <ul className="mobile-nav-list">
              {items.map((tab) => (
                <li key={tab.href}>
                  <Link href={tab.href} className="mobile-nav-link" data-active={pathname === tab.href}>
                    {t(tab.labelKey)}
                  </Link>
                </li>
              ))}
              {isAdmin ? (
                <li>
                  <Link href="/admin" className="mobile-nav-link" data-active={pathname === '/admin'}>
                    {t('nav.admin')}
                  </Link>
                </li>
              ) : null}
            </ul>
          </div>
        </div>
      ) : null}
    </>
  );
}

function MenuIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
      <path d="M2.5 4.5h13M2.5 9h13M2.5 13.5h13" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
      <path d="M4 4l10 10M14 4L4 14" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}
