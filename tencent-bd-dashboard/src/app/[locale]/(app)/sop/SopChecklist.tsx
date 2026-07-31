'use client';

import { useActionState, useEffect, useState } from 'react';
import { useTranslations } from 'next-intl';

import { CSRF_FIELD } from '@/lib/security/csrf-constants';
import { SubmitButton } from '@/components/SubmitButton';
import { saveSopChecklist } from '@/server/actions/board';
import type { FormActionState } from '@/server/actions/shared';

const initialState: FormActionState = {};

export function SopChecklist({
  initialSteps,
  canWrite,
  csrfToken,
}: {
  initialSteps: string[];
  canWrite: boolean;
  csrfToken: string;
}) {
  const t = useTranslations('sop');
  const tCommon = useTranslations('common');
  const [steps, setSteps] = useState(initialSteps.length > 0 ? initialSteps : ['']);
  const [state, formAction] = useActionState(saveSopChecklist, initialState);

  useEffect(() => {
    if (state.success) {
      // Nothing to reset -- the server-committed list already matches local
      // state; this effect exists so a future toast/notice has a clear hook.
    }
  }, [state.success]);

  return (
    <form action={formAction} className="stack">
      <input type="hidden" name={CSRF_FIELD} value={csrfToken} />

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

      {steps.map((step, index) => (
        <div className="row" key={index}>
          <input
            type="text"
            name="steps"
            value={step}
            placeholder={t('stepPlaceholder')}
            maxLength={2000}
            readOnly={!canWrite}
            onChange={(e) => setSteps((s) => s.map((v, i) => (i === index ? e.target.value : v)))}
            style={{ flex: 1 }}
          />
          {canWrite ? (
            <button type="button" className="danger" onClick={() => setSteps((s) => s.filter((_, i) => i !== index))}>
              x
            </button>
          ) : null}
        </div>
      ))}

      {canWrite ? (
        <div className="row">
          <button type="button" onClick={() => setSteps((s) => [...s, ''])}>
            {t('addStep')}
          </button>
          <SubmitButton className="primary" pendingLabel={tCommon('saving')}>
            {tCommon('save')}
          </SubmitButton>
        </div>
      ) : null}
    </form>
  );
}
