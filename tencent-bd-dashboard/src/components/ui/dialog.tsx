'use client';

import * as DialogPrimitive from '@radix-ui/react-dialog';
import { X } from 'lucide-react';
import type { ComponentProps } from 'react';

import { cn } from '@/lib/utils';

/**
 * Radix Dialog, replacing this project's hand-written modal.
 *
 * The bespoke version reimplemented a focus trap, focus restore, Escape
 * handling and an overlay-click guard by hand -- roughly sixty lines that
 * Radix already does correctly, including the parts the hand-rolled one
 * missed: `aria-hidden`/`inert` on the rest of the page for screen readers,
 * scroll-lock without layout shift, and pointer-event handling that
 * distinguishes a click from a text selection dragged out past the edge.
 */
export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogClose = DialogPrimitive.Close;
export const DialogPortal = DialogPrimitive.Portal;

export function DialogOverlay({ className, ...props }: ComponentProps<typeof DialogPrimitive.Overlay>) {
  return (
    <DialogPrimitive.Overlay
      data-slot="dialog-overlay"
      className={cn(
        'fixed inset-0 z-50 bg-[hsl(var(--shadow-color)/0.5)] backdrop-blur-[3px]',
        'data-[state=open]:animate-in data-[state=open]:fade-in-0',
        'data-[state=closed]:animate-out data-[state=closed]:fade-out-0',
        className,
      )}
      {...props}
    />
  );
}

export function DialogContent({
  className,
  children,
  wide = false,
  showClose = true,
  ...props
}: ComponentProps<typeof DialogPrimitive.Content> & { wide?: boolean; showClose?: boolean }) {
  return (
    <DialogPortal>
      <DialogOverlay />
      <DialogPrimitive.Content
        data-slot="dialog-content"
        className={cn(
          'fixed left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2',
          // Scrolls as one block rather than pinning a flex header/body/footer:
          // the callers render a varying number of siblings between their
          // header and footer (guidance panels, error banners, a conditional
          // form), so a three-region flex layout would strand whichever of
          // those sat outside the designated body element. The header and
          // footer instead stick within this scroll container, which gives the
          // same pinned chrome without constraining what goes between them.
          'max-h-[92dvh] w-[calc(100vw-2rem)] overflow-y-auto overscroll-contain',
          wide ? 'max-w-[1400px]' : 'max-w-[680px]',
          'rounded-[var(--radius-xl)] border border-[var(--glass-border)]',
          // Heavier blur than a card: a dialog has the whole page behind it,
          // so a light blur would leave the underlying table legible enough to
          // compete with the form on top of it.
          'bg-[var(--glass-bg-strong)] backdrop-blur-[28px]',
          'shadow-[0_1px_0_0_var(--glass-highlight)_inset,0_24px_64px_-12px_hsl(var(--shadow-color)/0.35)]',
          'data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95',
          'data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95',
          'duration-200',
          className,
        )}
        {...props}
      >
        {children}
        {showClose ? (
          <DialogPrimitive.Close
            data-slot="dialog-close"
            className={cn(
              'absolute right-4 top-4 grid size-7 place-items-center rounded-[var(--radius-sm)]',
              'text-[var(--muted)] transition-colors',
              'hover:bg-[var(--bg-subtle)] hover:text-[var(--ink)]',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]/55',
            )}
          >
            <X className="size-4" />
            <span className="sr-only">Close</span>
          </DialogPrimitive.Close>
        ) : null}
      </DialogPrimitive.Content>
    </DialogPortal>
  );
}

export function DialogHeader({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      data-slot="dialog-header"
      className={cn(
        'sticky top-0 z-10 flex flex-col gap-1 border-b border-[var(--line)] px-6 py-4 pr-14',
        // Opaque enough that scrolling content passing underneath does not
        // read through the sticky bar; a bare `backdrop-blur` here would
        // sample the dialog's own already-blurred backdrop and stay legible.
        'bg-[var(--dialog-chrome)] backdrop-blur-xl',
        className,
      )}
      {...props}
    />
  );
}

export function DialogFooter({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      data-slot="dialog-footer"
      className={cn(
        'sticky bottom-0 z-10 flex items-center justify-end gap-2',
        'border-t border-[var(--line)] bg-[var(--dialog-chrome)] px-6 py-3 backdrop-blur-xl',
        className,
      )}
      {...props}
    />
  );
}

export function DialogTitle({ className, ...props }: ComponentProps<typeof DialogPrimitive.Title>) {
  return (
    <DialogPrimitive.Title
      data-slot="dialog-title"
      className={cn('text-[15px] font-semibold tracking-[-0.01em] text-[var(--ink)]', className)}
      {...props}
    />
  );
}

export function DialogDescription({ className, ...props }: ComponentProps<typeof DialogPrimitive.Description>) {
  return (
    <DialogPrimitive.Description
      data-slot="dialog-description"
      className={cn('text-[13px] text-[var(--muted)]', className)}
      {...props}
    />
  );
}
