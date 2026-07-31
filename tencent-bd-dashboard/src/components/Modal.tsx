'use client';

import { useEffect, useRef } from 'react';
import type { ReactNode } from 'react';

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Presentational modal shell.
 *
 * Purely controlled by the caller's open/closed state -- this component holds
 * no state of its own beyond refs, so a caller that also drives a
 * `useActionState` form inside never has two sources of truth to reconcile.
 *
 * Traps focus while open and restores it to the element that opened the modal
 * on close: without this, a keyboard or screen-reader user can Tab straight
 * out of the dialog into the dimmed page behind it, and loses their place in
 * the underlying table entirely once the modal closes.
 */
export function Modal({
  title,
  onClose,
  children,
  wide = false,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  const boxRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);

  useEffect(() => {
    previouslyFocused.current = document.activeElement as HTMLElement | null;

    const box = boxRef.current;
    const focusable = box?.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR);
    (focusable?.[0] ?? box)?.focus();

    return () => {
      previouslyFocused.current?.focus();
    };
  }, []);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        onClose();
        return;
      }

      if (event.key !== 'Tab') return;

      const box = boxRef.current;
      if (!box) return;

      const focusable = Array.from(box.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
        (el) => el.offsetParent !== null,
      );
      if (focusable.length === 0) return;

      const first = focusable[0]!;
      const last = focusable[focusable.length - 1]!;
      const active = document.activeElement;

      // Cycle rather than let Tab escape into the dimmed page behind the
      // overlay: this is the whole of what a native focus trap buys, done by
      // hand because `Modal` predates this app's use of `<dialog>`.
      if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  return (
    // The overlay's own click closes the modal; a click that starts inside the
    // box and is only reported on the overlay via bubbling is excluded by the
    // ref check, so dragging a text selection out past the edge cannot
    // accidentally dismiss the form.
    <div
      className="modal-overlay"
      role="presentation"
      onMouseDown={(event) => {
        if (boxRef.current && !boxRef.current.contains(event.target as Node)) onClose();
      }}
    >
      <div
        className="modal-box"
        ref={boxRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        style={wide ? { width: 'min(1400px, 98vw)' } : undefined}
      >
        {children}
      </div>
    </div>
  );
}
