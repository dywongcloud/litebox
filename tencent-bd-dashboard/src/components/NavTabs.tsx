'use client';

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
 */
export function NavTabs({ grantedPermissions, isAdmin }: { grantedPermissions: readonly Permission[]; isAdmin: boolean }) {
  const t = useTranslations();
  const pathname = usePathname();
  const granted = new Set(grantedPermissions);

  return (
    <nav className="app-tabs">
      {TABS.filter((tab) => granted.has(tab.permission)).map((tab) => (
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
  );
}
