'use client';

import * as DialogPrimitive from '@radix-ui/react-dialog';
import { X } from 'lucide-react';
import type { ComponentProps } from 'react';

import { cn } from '@/lib/utils';

/**
 * Edge-anchored panel, used for the mobile navigation drawer.
 *
 * Built on Radix Dialog rather than a second primitive: a nav drawer is
 * modal in exactly the way a dialog is (focus is trapped in it, the page
 * behind is inert, Escape closes it), and the only real difference is where
 * it is anchored and how it animates in.
 */
export const Sheet = DialogPrimitive.Root;
export const SheetTrigger = DialogPrimitive.Trigger;
export const SheetClose = DialogPrimitive.Close;

export function SheetContent({
  className,
  children,
  side = 'left',
  ...props
}: ComponentProps<typeof DialogPrimitive.Content> & { side?: 'left' | 'right' }) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay
        className={cn(
          'fixed inset-0 z-50 bg-[hsl(var(--shadow-color)/0.5)] backdrop-blur-[3px]',
          'data-[state=open]:animate-in data-[state=open]:fade-in-0',
          'data-[state=closed]:animate-out data-[state=closed]:fade-out-0',
        )}
      />
      <DialogPrimitive.Content
        data-slot="sheet-content"
        className={cn(
          'fixed inset-y-0 z-50 flex h-full w-[min(20rem,86vw)] flex-col gap-4 p-5',
          'border-[var(--glass-border)] bg-[var(--glass-bg-strong)] backdrop-blur-[28px]',
          'shadow-[0_24px_64px_-12px_hsl(var(--shadow-color)/0.35)]',
          'transition ease-[var(--ease-out)] data-[state=closed]:duration-200 data-[state=open]:duration-300',
          side === 'left'
            ? 'left-0 border-r data-[state=open]:animate-in data-[state=open]:slide-in-from-left data-[state=closed]:animate-out data-[state=closed]:slide-out-to-left'
            : 'right-0 border-l data-[state=open]:animate-in data-[state=open]:slide-in-from-right data-[state=closed]:animate-out data-[state=closed]:slide-out-to-right',
          className,
        )}
        {...props}
      >
        {children}
        <DialogPrimitive.Close
          className={cn(
            'absolute right-4 top-4 grid size-7 place-items-center rounded-[var(--radius-sm)]',
            'text-[var(--muted)] transition-colors hover:bg-[var(--bg-subtle)] hover:text-[var(--ink)]',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]/55',
          )}
        >
          <X className="size-4" />
          <span className="sr-only">Close</span>
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}

export function SheetTitle({ className, ...props }: ComponentProps<typeof DialogPrimitive.Title>) {
  return (
    <DialogPrimitive.Title
      data-slot="sheet-title"
      className={cn('pr-10 text-[14px] font-semibold tracking-[-0.01em] text-[var(--ink)]', className)}
      {...props}
    />
  );
}

export function SheetDescription({ className, ...props }: ComponentProps<typeof DialogPrimitive.Description>) {
  return (
    <DialogPrimitive.Description data-slot="sheet-description" className={cn('text-[12px] text-[var(--muted)]', className)} {...props} />
  );
}
