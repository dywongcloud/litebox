'use client';

import { useEffect, useRef } from 'react';
import type { ReactNode } from 'react';

/**
 * Presentational modal shell.
 *
 * Purely controlled by the caller's open/closed state -- this component holds
 * no state of its own beyond a ref, so a caller that also drives a
 * `useActionState` form inside never has two sources of truth to reconcile.
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

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') onClose();
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
      <div className="modal-box" ref={boxRef} role="dialog" aria-modal="true" aria-label={title} style={wide ? { width: 'min(1400px, 98vw)' } : undefined}>
        {children}
      </div>
    </div>
  );
}
