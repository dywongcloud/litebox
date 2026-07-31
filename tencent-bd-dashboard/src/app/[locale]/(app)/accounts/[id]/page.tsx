import { getTranslations } from 'next-intl/server';
import { notFound } from 'next/navigation';

import { can } from '@/lib/auth/rbac';
import * as session from '@/lib/auth/session';
import { readToken } from '@/lib/security/csrf';
import { Link } from '@/i18n/navigation';
import { getAccount, getAccountResearch } from '@/server/data/accounts';

import { ResearchForm } from './ResearchForm';

export default async function AccountResearchPage({ params }: { params: Promise<{ id: string }> }) {
  const active = await session.current();
  if (!active) return null;

  const { id } = await params;
  const accountId = Number(id);
  if (!Number.isInteger(accountId) || accountId <= 0) notFound();

  const account = getAccount(accountId);
  if (!account) notFound();

  const research = getAccountResearch(accountId);
  const t = await getTranslations('research');
  const canWrite = can(active.user.role, 'account.write');
  const csrfToken = await readToken(active.sessionId);

  return (
    <div className="stack">
      <div className="spread">
        <div>
          <Link href="/accounts" className="small">
            {'<- '}
            {t('backToPipeline')}
          </Link>
          <h1 style={{ margin: '6px 0 0', fontSize: 20 }}>{account.company}</h1>
        </div>
      </div>

      <ResearchForm accountId={accountId} research={research} canWrite={canWrite} csrfToken={csrfToken} />
    </div>
  );
}
