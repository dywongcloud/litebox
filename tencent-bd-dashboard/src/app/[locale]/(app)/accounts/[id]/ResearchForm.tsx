'use client';

import { useActionState, useState } from 'react';
import { useTranslations } from 'next-intl';

import type { AccountResearch } from '@/db/schema';
import { CSRF_FIELD } from '@/lib/security/csrf-constants';
import { TextAreaField, TextField } from '@/components/fields';
import { SubmitButton } from '@/components/SubmitButton';
import { saveResearch } from '@/server/actions/accounts';
import type { FormActionState } from '@/server/actions/shared';

const initialState: FormActionState = {};

const TABS = ['research', 'thesis', 'buying', 'evidence'] as const;
type Tab = (typeof TABS)[number];

export function ResearchForm({
  accountId,
  research,
  canWrite,
  csrfToken,
}: {
  accountId: number;
  research: AccountResearch | undefined;
  canWrite: boolean;
  csrfToken: string;
}) {
  const t = useTranslations('research');
  const tCommon = useTranslations('common');
  const [tab, setTab] = useState<Tab>('research');
  const [state, formAction] = useActionState(saveResearch, initialState);

  const r = research;

  return (
    <form action={formAction}>
      <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
      <input type="hidden" name="accountId" value={accountId} />

      {state.message ? (
        <p className="form-message" data-tone="error" role="alert">
          {state.message}
        </p>
      ) : null}
      {state.success ? (
        <p className="form-message" data-tone="success" role="status">
          {tCommon('saved')}
        </p>
      ) : null}

      <div className="row" style={{ marginBottom: 12 }}>
        {TABS.map((key) => (
          <button
            key={key}
            type="button"
            className={tab === key ? 'primary' : undefined}
            onClick={() => setTab(key)}
          >
            {t(`tab${capitalize(key)}` as 'tabResearch')}
          </button>
        ))}
      </div>

      <div style={{ display: tab === 'research' ? 'block' : 'none' }}>
        <div className="grid-2">
          <TextAreaField label={t('companySnapshot')} name="companySnapshot" defaultValue={r?.companySnapshot} hint={t('companySnapshotHint')} />
          <TextAreaField label={t('recentNews')} name="recentNews" defaultValue={r?.recentNews} hint={t('recentNewsHint')} />
          <TextAreaField label={t('funding')} name="funding" defaultValue={r?.funding} hint={t('fundingHint')} />
          <TextAreaField label={t('stack')} name="stack" defaultValue={r?.stack} hint={t('stackHint')} />
          <TextAreaField label={t('hiring')} name="hiring" defaultValue={r?.hiring} hint={t('hiringHint')} />
          <TextAreaField label={t('vendors')} name="vendors" defaultValue={r?.vendors} hint={t('vendorsHint')} />
          <TextAreaField label={t('triggers')} name="triggers" defaultValue={r?.triggers} hint={t('triggersHint')} />
          <TextAreaField label={t('pains')} name="pains" defaultValue={r?.pains} hint={t('painsHint')} />
          <TextAreaField className="full" label={t('gaps')} name="gaps" defaultValue={r?.gaps} hint={t('gapsHint')} />
        </div>
      </div>

      <div style={{ display: tab === 'thesis' ? 'block' : 'none' }}>
        <div className="card thesis-box" style={{ marginBottom: 12 }}>
          <b>{t('thesisFormulaTitle')}</b>
          <p>{t('thesisFormulaBody')}</p>
        </div>
        <div className="grid-2">
          <TextAreaField label={t('whyAccount')} name="whyAccount" defaultValue={r?.whyAccount} />
          <TextAreaField label={t('whyNow')} name="whyNow" defaultValue={r?.whyNow} />
          <TextAreaField label={t('primaryPain')} name="primaryPain" defaultValue={r?.primaryPain} />
          <TextAreaField label={t('wedge')} name="wedge" defaultValue={r?.wedge} />
          <TextAreaField label={t('buyer')} name="buyer" defaultValue={r?.buyer} />
          <TextAreaField label={t('proof')} name="proof" defaultValue={r?.proof} />
          <TextAreaField label={t('expansion')} name="expansion" defaultValue={r?.expansion} />
          <TextAreaField label={t('validationStep')} name="validationStep" defaultValue={r?.validationStep} />
          <TextAreaField className="full" label={t('finalThesis')} name="finalThesis" defaultValue={r?.finalThesis} />
        </div>
      </div>

      <div style={{ display: tab === 'buying' ? 'block' : 'none' }}>
        <div className="grid-2">
          <TextAreaField label={t('economicBuyer')} name="economicBuyer" defaultValue={r?.economicBuyer} />
          <TextAreaField label={t('technicalBuyer')} name="technicalBuyer" defaultValue={r?.technicalBuyer} />
          <TextAreaField label={t('champion')} name="champion" defaultValue={r?.champion} />
          <TextAreaField label={t('users')} name="usersInfluence" defaultValue={r?.usersInfluence} />
          <TextAreaField label={t('blockers')} name="blockers" defaultValue={r?.blockers} />
          <TextAreaField label={t('procurement')} name="procurement" defaultValue={r?.procurement} />
          <TextAreaField className="full" label={t('warmPath')} name="warmPath" defaultValue={r?.warmPath} />
        </div>
      </div>

      <div style={{ display: tab === 'evidence' ? 'block' : 'none' }}>
        <div className="grid-2">
          <TextAreaField className="full" label={t('sources')} name="sources" defaultValue={r?.sources} hint={t('sourcesHint')} />
          <TextField label={t('confidence')} name="confidence" defaultValue={r?.confidence} />
          <TextField label={t('lastVerified')} name="lastVerified" type="date" defaultValue={r?.lastVerified} />
        </div>
      </div>

      {canWrite ? (
        <div className="row" style={{ marginTop: 16, justifyContent: 'flex-end' }}>
          <SubmitButton className="primary" pendingLabel={tCommon('saving')}>
            {t('save')}
          </SubmitButton>
        </div>
      ) : null}
    </form>
  );
}

function capitalize<T extends string>(value: T): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
