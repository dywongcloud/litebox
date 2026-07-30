'use client';

import { useFormStatus } from 'react-dom';
import type { ComponentProps } from 'react';

/**
 * Submit button that disables itself and shows a pending label while its
 * enclosing form's Server Action is in flight.
 *
 * Must be a separate component: `useFormStatus` only reports the status of the
 * nearest enclosing `<form>`, so it has to render *inside* that form rather
 * than in the same component that renders the form tag.
 */
export function SubmitButton({
  pendingLabel,
  children,
  ...rest
}: ComponentProps<'button'> & { pendingLabel?: string }) {
  const { pending } = useFormStatus();

  return (
    <button type="submit" disabled={pending} {...rest}>
      {pending ? (pendingLabel ?? children) : children}
    </button>
  );
}
