'use client';

import { useEffect } from 'react';
import { useTranslations } from 'next-intl';

/**
 * Route error boundary.
 *
 * Deliberately shows nothing about `error` beyond a generic message: a stack
 * trace or error message can carry file paths, query fragments, or internal
 * identifiers, none of which belong on a page a customer-facing BD rep might
 * have open. The real detail goes to the server console via `console.error`,
 * which is picked up by whatever the deployment uses for log aggregation.
 */
export default function LocaleError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  const t = useTranslations('errors');

  useEffect(() => {
    console.error('[app-error]', error.digest ?? error.message);
  }, [error]);

  return (
    <div
      className="empty-state"
      style={{ minHeight: '60dvh', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', gap: 12 }}
    >
      <h1 style={{ margin: 0 }}>{t('serverError')}</h1>
      <p style={{ maxWidth: 420 }}>{t('serverErrorBody')}</p>
      <button type="button" className="primary" onClick={reset}>
        {t('generic')}
      </button>
    </div>
  );
}
