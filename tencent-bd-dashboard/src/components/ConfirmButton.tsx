'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';

/**
 * Two-step inline confirmation, replacing `window.confirm` for destructive
 * actions.
 *
 * A native `confirm()` blocks the entire page on an unstyled, un-ownable
 * browser dialog -- wrong register for a themed premium UI, and impossible to
 * make consistent between locales beyond the string it shows. This renders
 * in place of the trigger button: a first click swaps it for an inline
 * "Delete this? [Delete] [Cancel]" strip; only the second click's `type="submit"`
 * actually submits the enclosing form. Must be rendered inside the `<form>`
 * it confirms.
 */
export function ConfirmButton({
  label,
  className = 'danger',
}: {
  label: string;
  className?: string;
}) {
  const tCommon = useTranslations('common');
  const [confirming, setConfirming] = useState(false);

  if (!confirming) {
    return (
      <button type="button" className={className} onClick={() => setConfirming(true)}>
        {label}
      </button>
    );
  }

  return (
    <span className="confirm-inline">
      <span>{tCommon('confirmDelete')}</span>
      <button type="submit" className="danger">
        {label}
      </button>
      <button type="button" onClick={() => setConfirming(false)}>
        {tCommon('cancel')}
      </button>
    </span>
  );
}
