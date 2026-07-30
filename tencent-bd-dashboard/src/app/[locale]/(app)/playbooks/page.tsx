import { getTranslations } from 'next-intl/server';

import { can } from '@/lib/auth/rbac';
import * as session from '@/lib/auth/session';
import { readToken } from '@/lib/security/csrf';
import { FilterForm } from '@/components/FilterForm';
import { listMotions } from '@/server/data/board';

import { PlaybooksClient } from './PlaybooksClient';

export default async function PlaybooksPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const active = await session.current();
  if (!active) return null;

  const { q } = await searchParams;
  const query = typeof q === 'string' ? q : '';

  const t = await getTranslations('playbooks');
  const motions = listMotions(query);
  const canWrite = can(active.user.role, 'playbook.write');
  const csrfToken = await readToken(active.sessionId);

  return (
    <>
      <div className="workspace-banner">
        <div className="workspace-card">
          <h3>{t('bannerLibraryTitle')}</h3>
          <p>{t('bannerLibraryBody')}</p>
        </div>
        <div className="workspace-card">
          <h3>{t('bannerUsageTitle')}</h3>
          <p>{t('bannerUsageBody')}</p>
        </div>
      </div>

      <FilterForm>
        <input className="search" type="search" name="q" placeholder={t('searchPlaceholder')} defaultValue={query} />
      </FilterForm>

      <PlaybooksClient items={motions} canWrite={canWrite} csrfToken={csrfToken} />
    </>
  );
}
