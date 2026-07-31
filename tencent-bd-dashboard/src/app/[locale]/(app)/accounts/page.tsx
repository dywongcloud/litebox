import { getTranslations } from 'next-intl/server';

import { ACCOUNT_STAGES } from '@/domain/enums';
import { accountFilterSchema } from '@/domain/schemas';
import { can } from '@/lib/auth/rbac';
import * as session from '@/lib/auth/session';
import { readToken } from '@/lib/security/csrf';
import { FilterForm } from '@/components/FilterForm';
import { listAccounts } from '@/server/data/accounts';

import { AccountsClient } from './AccountsClient';

export default async function AccountsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const active = await session.current();
  if (!active) return null;

  const raw = await searchParams;
  const filter = accountFilterSchema.parse({ q: raw.q, stage: raw.stage, page: raw.page });

  const [t, tCommon, list] = await Promise.all([
    getTranslations('accounts'),
    getTranslations('common'),
    Promise.resolve(listAccounts(filter)),
  ]);

  const canWrite = can(active.user.role, 'account.write');
  const canDelete = can(active.user.role, 'account.delete');
  const csrfToken = await readToken(active.sessionId);

  return (
    <>
      <div className="workspace-banner">
        <div className="workspace-card">
          <h3>{t('bannerWorkspaceTitle')}</h3>
          <p>{t('bannerWorkspaceBody')}</p>
        </div>
        <div className="workspace-card">
          <h3>{t('bannerThesisTitle')}</h3>
          <p>{t('bannerThesisBody')}</p>
        </div>
      </div>

      <FilterForm>
        <input className="search" type="search" name="q" placeholder={t('searchPlaceholder')} defaultValue={filter.q} />
        <select name="stage" defaultValue={filter.stage}>
          <option value="">{t('filterStage')}</option>
          {ACCOUNT_STAGES.map((stage) => (
            <option key={stage} value={stage}>
              {stage}
            </option>
          ))}
        </select>
        <noscript>
          <button type="submit">{tCommon('filter')}</button>
        </noscript>
      </FilterForm>

      <AccountsClient
        items={list.items}
        total={list.total}
        page={list.page}
        pageSize={list.pageSize}
        canWrite={canWrite}
        canDelete={canDelete}
        csrfToken={csrfToken}
      />
    </>
  );
}
