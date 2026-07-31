import { getTranslations } from 'next-intl/server';

import { can } from '@/lib/auth/rbac';
import * as session from '@/lib/auth/session';
import { readToken } from '@/lib/security/csrf';
import { listSopSteps } from '@/server/data/board';

import { SopChecklist } from './SopChecklist';

const STAGES = [0, 1, 2, 3, 4, 5] as const;

export default async function SopPage() {
  const active = await session.current();
  if (!active) return null;

  const t = await getTranslations('sop');
  const steps = listSopSteps();
  const canWrite = can(active.user.role, 'playbook.write');
  const csrfToken = await readToken(active.sessionId);

  return (
    <div className="stack">
      <div className="grid-3">
        {STAGES.map((stage) => (
          <div className="card" key={stage}>
            <h3>{t(`stage${stage}Title` as 'stage0Title')}</h3>
            <p>{t(`stage${stage}Body` as 'stage0Body')}</p>
          </div>
        ))}
      </div>

      <div className="card">
        <h3>{t('checklistTitle')}</h3>
        <SopChecklist initialSteps={steps.map((s) => s.body)} canWrite={canWrite} csrfToken={csrfToken} />
      </div>
    </div>
  );
}
