'use client';

import * as LabelPrimitive from '@radix-ui/react-label';
import type { ComponentProps } from 'react';

import { cn } from '@/lib/utils';

const fieldBase = cn(
  'w-full rounded-[var(--radius-md)] border border-[var(--line-strong)]',
  'bg-[var(--panel)]/70 px-3 text-[13px] text-[var(--ink)] backdrop-blur-sm',
  'transition-[border-color,box-shadow,background-color] duration-150',
  'placeholder:text-[var(--gray-400)]',
  'hover:border-[var(--gray-400)]',
  'focus-visible:outline-none focus-visible:border-[var(--brand)]',
  'focus-visible:ring-[3px] focus-visible:ring-[var(--focus-ring)]/18',
  'focus-visible:bg-[var(--panel)]',
  'disabled:cursor-not-allowed disabled:opacity-55',
  'aria-[invalid=true]:border-[var(--danger)] aria-[invalid=true]:ring-[var(--danger)]/18',
);

export function Input({ className, ...props }: ComponentProps<'input'>) {
  return <input data-slot="input" className={cn(fieldBase, 'h-9', className)} {...props} />;
}

export function Textarea({ className, ...props }: ComponentProps<'textarea'>) {
  return <textarea data-slot="textarea" className={cn(fieldBase, 'min-h-20 resize-y py-2 leading-relaxed', className)} {...props} />;
}

/**
 * Native `<select>`, styled to match. Distinct from the Radix `Select` in
 * `select.tsx`: this one stays in the DOM as a real form control, so it still
 * submits inside a `<form>` without JavaScript -- which the filter bars and
 * the board's status control rely on.
 */
export function NativeSelect({ className, ...props }: ComponentProps<'select'>) {
  return (
    <select
      data-slot="native-select"
      className={cn(
        fieldBase,
        'h-9 cursor-pointer appearance-none bg-no-repeat pr-8',
        // Inline chevron as a data URI: an SVG sibling would need absolute
        // positioning and a wrapper, and `appearance: none` removes the
        // platform arrow that would otherwise be there.
        "bg-[url(\"data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='none' stroke='%236b7484' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m4 6 4 4 4-4'/%3E%3C/svg%3E\")]",
        'bg-[position:right_0.6rem_center] bg-[size:1rem]',
        className,
      )}
      {...props}
    />
  );
}

export function Label({ className, ...props }: ComponentProps<typeof LabelPrimitive.Root>) {
  return (
    <LabelPrimitive.Root
      data-slot="label"
      className={cn(
        'flex items-center gap-1.5 text-[12px] font-[550] text-[var(--ink-secondary)]',
        'select-none peer-disabled:opacity-55',
        className,
      )}
      {...props}
    />
  );
}

export { fieldBase };
