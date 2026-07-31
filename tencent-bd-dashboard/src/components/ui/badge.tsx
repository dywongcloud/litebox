import { cva } from 'class-variance-authority';
import type { VariantProps } from 'class-variance-authority';
import type { ComponentProps } from 'react';

import { cn } from '@/lib/utils';

const badgeVariants = cva(
  cn(
    'inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5',
    'text-[11px] font-[550] leading-[1.45] whitespace-nowrap',
    // Priority codes and score counts sit next to each other in tables; lining
    // figures keep them from jittering column to column.
    'font-variant-numeric-[tabular-nums]',
  ),
  {
    variants: {
      tone: {
        neutral: 'border-[var(--line)] bg-[var(--bg-subtle)] text-[var(--ink-secondary)]',
        brand: 'border-[var(--brand-200)] bg-[var(--brand-50)] text-[var(--brand-700)]',
        success: 'border-[var(--success-border)] bg-[var(--success-bg)] text-[var(--success)]',
        warn: 'border-[var(--warn-border)] bg-[var(--warn-bg)] text-[var(--warn)]',
        danger: 'border-[var(--danger-border)] bg-[var(--danger-bg)] text-[var(--danger)]',
        outline: 'border-[var(--line-strong)] bg-transparent text-[var(--ink-secondary)]',
      },
    },
    defaultVariants: { tone: 'neutral' },
  },
);

export function Badge({ className, tone, ...props }: ComponentProps<'span'> & VariantProps<typeof badgeVariants>) {
  return <span data-slot="badge" className={cn(badgeVariants({ tone }), className)} {...props} />;
}

/** Small leading status dot, for a badge that reports live state. */
export function BadgeDot({ className, ...props }: ComponentProps<'span'>) {
  return <span data-slot="badge-dot" className={cn('size-1.5 rounded-full bg-current opacity-70', className)} {...props} />;
}

export { badgeVariants };
