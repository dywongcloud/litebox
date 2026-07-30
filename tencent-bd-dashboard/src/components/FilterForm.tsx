'use client';

import { useRef } from 'react';
import type { ReactNode } from 'react';

/**
 * A `GET` filter form that resubmits itself whenever a control inside it
 * changes.
 *
 * Progressive by construction: without JavaScript this is an ordinary form
 * with browser-default submit-on-Enter and no auto-submit, and the "Apply"
 * button (rendered by the caller) still submits it. With JavaScript, changing
 * a select or typing (debounced) in a text field updates the URL immediately.
 * All filter *state* lives in the URL query string and is parsed server-side
 * by `productFilterSchema`/`accountFilterSchema`/etc, so this component never
 * needs to reach across a fetch boundary -- it only ever triggers a normal
 * navigation.
 */
export function FilterForm({ children, action }: { children: ReactNode; action?: string }) {
  const formRef = useRef<HTMLFormElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  return (
    <form
      ref={formRef}
      action={action}
      method="get"
      className="toolbar"
      onChange={(event) => {
        const target = event.target as HTMLElement;
        // Selects submit immediately; free-text search is debounced so every
        // keystroke does not trigger a navigation.
        if (target.tagName === 'SELECT') {
          formRef.current?.requestSubmit();
        }
      }}
      onInput={(event) => {
        const target = event.target as HTMLElement;
        if (target.tagName !== 'INPUT') return;
        if (debounceRef.current) clearTimeout(debounceRef.current);
        debounceRef.current = setTimeout(() => formRef.current?.requestSubmit(), 350);
      }}
    >
      {children}
    </form>
  );
}
