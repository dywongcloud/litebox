'use client';

import { useActionState } from 'react';
import { useTranslations } from 'next-intl';

import { SubmitButton } from '@/components/SubmitButton';
import { login, type LoginState } from '@/server/actions/auth';

const initialState: LoginState = {};

export function LoginForm({ next }: { next?: string }) {
  const t = useTranslations('auth');
  const [state, formAction] = useActionState(login, initialState);

  return (
    <form action={formAction} className="stack" noValidate>
      {next ? <input type="hidden" name="next" value={next} /> : null}

      {state.message ? (
        <p className="form-message" data-tone="error" role="alert">
          {state.message}
        </p>
      ) : null}

      <label>
        {t('email')}
        <input type="email" name="email" required autoComplete="email" autoFocus maxLength={254} />
        {state.errors?.email ? (
          <span className="field-error" role="alert">
            {state.errors.email[0]}
          </span>
        ) : null}
      </label>

      <label>
        {t('password')}
        <input type="password" name="password" required autoComplete="current-password" maxLength={200} />
      </label>

      <SubmitButton className="primary" pendingLabel={t('submitting')}>
        {t('submit')}
      </SubmitButton>
    </form>
  );
}
