'use client';

import { useActionState, useState } from 'react';
import { useTranslations } from 'next-intl';

import type { Locale } from '@/domain/enums';
import { LOCALES } from '@/domain/enums';
import type { TranslatableEntity } from '@/domain/schemas';
import { CSRF_FIELD } from '@/lib/security/csrf-constants';
import { requestTranslation, type TranslateState } from '@/server/actions/translation';

import { SubmitButton } from './SubmitButton';

const initialState: TranslateState = {};

/**
 * Inline translation control for one field of one record.
 *
 * Deliberately shown as a request-and-review affordance rather than an
 * always-on live translation: every result carries its origin (script
 * conversion vs machine) and, for machine output, an explicit "not reviewed"
 * notice. Nothing here overwrites the source field -- it only produces a
 * translation record a rep can read alongside the original.
 */
export function TranslateField({
  entityType,
  entityId,
  field,
  sourceLocale,
  csrfToken,
}: {
  entityType: TranslatableEntity;
  entityId: number;
  field: string;
  sourceLocale: Locale;
  csrfToken: string;
}) {
  const t = useTranslations('translation');
  const tCommon = useTranslations('common');
  const [target, setTarget] = useState<Locale>(sourceLocale === 'en' ? 'zh-Hans' : 'en');
  const [state, formAction] = useActionState(requestTranslation, initialState);
  const [expanded, setExpanded] = useState(false);

  const targets = LOCALES.filter((l) => l !== sourceLocale);

  return (
    <div className="small" style={{ marginTop: 6, borderTop: '1px dashed var(--line)', paddingTop: 6 }}>
      {!expanded ? (
        <button type="button" onClick={() => setExpanded(true)}>
          {t('title')}
        </button>
      ) : (
        <form action={formAction} className="row">
          <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
          <input type="hidden" name="entityType" value={entityType} />
          <input type="hidden" name="entityId" value={entityId} />
          <input type="hidden" name="field" value={field} />
          <input type="hidden" name="sourceLocale" value={sourceLocale} />
          <input type="hidden" name="targetLocale" value={target} />

          <select value={target} onChange={(e) => setTarget(e.target.value as Locale)} style={{ width: 'auto' }} aria-label={t('targetLocale')}>
            {targets.map((locale) => (
              <option key={locale} value={locale}>
                {locale}
              </option>
            ))}
          </select>
          <SubmitButton pendingLabel={t('translating')}>{t('translate')}</SubmitButton>
          <button type="button" onClick={() => setExpanded(false)}>
            {tCommon('close')}
          </button>

          {state.message ? <span className="field-error">{state.message}</span> : null}
          {state.success && state.value !== undefined ? (
            <div className="full" style={{ width: '100%', marginTop: 6 }}>
              <p className="small" style={{ whiteSpace: 'pre-wrap' }}>
                {state.value || <em>{t('scriptOnly')}</em>}
              </p>
              <span className="pill" data-tone="warn">
                {t('machineWarning')}
              </span>
            </div>
          ) : null}
        </form>
      )}
    </div>
  );
}
