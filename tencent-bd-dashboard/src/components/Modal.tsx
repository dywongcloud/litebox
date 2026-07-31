'use client';

import type { ReactNode } from 'react';

import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog';

/**
 * Compatibility shell over the Radix dialog in `ui/dialog.tsx`.
 *
 * Keeps the call signature the six existing dialogs already use -- they mount
 * this conditionally and hand it an `onClose`, rather than driving an `open`
 * prop -- so swapping the implementation underneath moved no call sites. The
 * hand-written version this replaces reimplemented a focus trap, focus
 * restore, Escape handling and an overlay-click guard in about sixty lines;
 * all four now come from Radix, along with the page-inerting and scroll-lock
 * the hand-rolled one never had.
 *
 * `open` is hard-coded true because mounting *is* the open signal in this
 * API; `onOpenChange` fires only on a close request, which is forwarded to
 * `onClose` so the parent unmounts us.
 *
 * The visible heading is supplied by each caller's own `.modal-header`, so the
 * `DialogTitle` Radix requires for `aria-labelledby` is rendered visually
 * hidden rather than duplicated on screen -- omitting it entirely would leave
 * the dialog unlabelled for a screen reader.
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
  return (
    <Dialog
      open
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <DialogContent wide={wide} showClose={false}>
        <DialogTitle className="sr-only">{title}</DialogTitle>
        {children}
      </DialogContent>
    </Dialog>
  );
}
