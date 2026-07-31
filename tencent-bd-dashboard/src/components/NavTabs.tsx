'use client';

import { Menu } from 'lucide-react';
import { useState } from 'react';
import { useTranslations } from 'next-intl';

import { Link, usePathname } from '@/i18n/navigation';
import type { Permission } from '@/lib/auth/rbac';
import { Sheet, SheetClose, SheetContent, SheetTitle, SheetTrigger } from '@/components/ui/sheet';

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
 *
 * The drawer is a Radix Sheet. The version this replaces hand-rolled the
 * overlay, the Escape handler, the body scroll-lock and the backdrop-click
 * dismissal; Radix covers all four and additionally marks the page behind as
 * inert, which the hand-rolled one never did -- a screen reader could still
 * walk into the page underneath the open drawer.
 */
export function NavTabs({ grantedPermissions, isAdmin }: { grantedPermissions: readonly Permission[]; isAdmin: boolean }) {
  const t = useTranslations();
  const pathname = usePathname();
  const granted = new Set(grantedPermissions);
  const [open, setOpen] = useState(false);

  // Closing the drawer on navigation is state derived from a prop
  // (`pathname`) changing, not a side effect on an external system -- doing it
  // during render (React's documented pattern) avoids the extra render pass a
  // `useEffect` + `setState` round trip would cost.
  const [renderedForPathname, setRenderedForPathname] = useState(pathname);
  if (pathname !== renderedForPathname) {
    setRenderedForPathname(pathname);
    setOpen(false);
  }

  const items = TABS.filter((tab) => granted.has(tab.permission));
  const allItems = [...items, ...(isAdmin ? [{ href: '/admin' as const, labelKey: 'nav.admin' as const }] : [])];
  const activeItem = allItems.find((tab) => tab.href === pathname);

  return (
    <>
      <nav className="app-tabs desktop-tabs" aria-label="Primary">
        {allItems.map((tab) => (
          <Link key={tab.href} href={tab.href} className="app-tab" data-active={pathname === tab.href}>
            {t(tab.labelKey)}
          </Link>
        ))}
      </nav>

      <div className="mobile-nav">
        <Sheet open={open} onOpenChange={setOpen}>
          <SheetTrigger className="mobile-nav-trigger">
            <Menu className="size-[18px]" aria-hidden="true" />
            <span>{activeItem ? t(activeItem.labelKey) : t('nav.products')}</span>
          </SheetTrigger>
          <SheetContent side="left">
            <SheetTitle>{t('app.title')}</SheetTitle>
            <ul className="mobile-nav-list">
              {allItems.map((tab) => (
                <li key={tab.href}>
                  <SheetClose asChild>
                    <Link href={tab.href} className="mobile-nav-link" data-active={pathname === tab.href}>
                      {t(tab.labelKey)}
                    </Link>
                  </SheetClose>
                </li>
              ))}
            </ul>
          </SheetContent>
        </Sheet>
      </div>
    </>
  );
}
