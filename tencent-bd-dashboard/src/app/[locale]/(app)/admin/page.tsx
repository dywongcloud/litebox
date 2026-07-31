import { getTranslations } from 'next-intl/server';
import { redirect } from 'next/navigation';

import { USER_ROLES } from '@/domain/enums';
import * as session from '@/lib/auth/session';
import { readToken } from '@/lib/security/csrf';
import { hasTencentCredentials } from '@/lib/env';
import { listUsers } from '@/server/data/users';
import { listNeedingReview } from '@/server/data/translations';
import { getLastSyncRun } from '@/server/catalog/sync';
import { loadAuditLog } from '@/server/actions/data-export';

import { AdminClient } from './AdminClient';

export default async function AdminPage({ params }: { params: Promise<{ locale: string }> }) {
  const active = await session.current();
  if (!active) return null;

  const { locale } = await params;
  if (active.user.role !== 'admin') {
    redirect(`/${locale}/products`);
  }

  const t = await getTranslations('admin');
  const users = listUsers();
  const pendingTranslations = listNeedingReview();
  const lastSync = getLastSyncRun();
  const auditResult = await loadAuditLog();
  const csrfToken = await readToken(active.sessionId);

  return (
    <div className="stack">
      <h2 style={{ margin: 0 }}>{t('heading')}</h2>

      <AdminClient
        currentUserId={active.user.id}
        users={users.map((u) => ({
          id: u.id,
          email: u.email,
          displayName: u.displayName,
          role: u.role,
          isActive: u.isActive,
          lastLoginAt: u.lastLoginAt?.toISOString() ?? null,
          createdAt: u.createdAt.toISOString(),
        }))}
        roles={USER_ROLES}
        pendingTranslations={pendingTranslations.map((tr) => ({
          id: tr.id,
          entityType: tr.entityType,
          entityId: tr.entityId,
          field: tr.field,
          locale: tr.locale,
          value: tr.value,
          origin: tr.origin,
        }))}
        auditEntries={auditResult.entries ?? []}
        lastSync={
          lastSync
            ? { status: lastSync.status, finishedAt: lastSync.finishedAt?.toISOString() ?? null, sourceKind: lastSync.sourceKind, error: lastSync.error }
            : null
        }
        hasTencentCredentials={hasTencentCredentials}
        csrfToken={csrfToken}
      />
    </div>
  );
}
