'use client';

import { Slot } from '@radix-ui/react-slot';
import { cva } from 'class-variance-authority';
import type { VariantProps } from 'class-variance-authority';
import type { ComponentProps } from 'react';

import { cn } from '@/lib/utils';

/**
 * Every variant carries `data-slot="button"`, which is what keeps the legacy
 * `button:not([data-slot])` rules in `globals.css` from reaching in and
 * re-styling these. Drop the attribute and the old border/background bleeds
 * back through on the variants that intentionally have none (ghost, link).
 */
const buttonVariants = cva(
  cn(
    'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-[var(--radius-md)]',
    'text-[13px] font-[550] leading-tight transition-all duration-150',
    'outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]/55 focus-visible:ring-offset-1',
    'focus-visible:ring-offset-[var(--bg)]',
    'disabled:pointer-events-none disabled:opacity-50',
    "[&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 [&_svg]:shrink-0",
    'active:translate-y-px',
  ),
  {
    variants: {
      variant: {
        // The lift is what reads as "premium": a saturated fill alone looks
        // flat, so the brand button gets a top-light gradient plus a coloured
        // glow that intensifies on hover.
        primary: cn(
          'text-white border border-[var(--brand-600)]',
          'bg-[linear-gradient(180deg,var(--brand-400),var(--brand-600))]',
          'shadow-[0_1px_0_0_rgba(255,255,255,0.18)_inset,0_2px_8px_-1px_var(--brand-glow),0_1px_2px_rgba(0,0,0,0.15)]',
          'hover:bg-[linear-gradient(180deg,var(--brand-300),var(--brand-500))]',
          'hover:shadow-[0_1px_0_0_rgba(255,255,255,0.22)_inset,0_4px_16px_-2px_var(--brand-glow-strong),0_1px_2px_rgba(0,0,0,0.15)]',
        ),
        // Glass: the default for chrome that sits over the ambient field.
        glass: cn(
          'border border-[var(--glass-border)] text-[var(--ink)]',
          'bg-[var(--glass-bg)] backdrop-blur-[var(--glass-blur)]',
          'shadow-[0_1px_0_0_var(--glass-highlight)_inset,0_1px_2px_rgba(0,0,0,0.04)]',
          'hover:bg-[var(--glass-bg-strong)] hover:border-[var(--line-strong)]',
        ),
        outline: cn(
          'border border-[var(--line-strong)] bg-[var(--panel)] text-[var(--ink)]',
          'hover:bg-[var(--panel-hover)] hover:border-[var(--gray-400)]',
        ),
        ghost: 'text-[var(--ink-secondary)] hover:bg-[var(--bg-subtle)] hover:text-[var(--ink)]',
        destructive: cn(
          'border border-[var(--danger)]/40 text-[var(--danger)]',
          'bg-[var(--danger-bg)] hover:bg-[var(--danger)] hover:text-white hover:border-[var(--danger)]',
        ),
        link: 'text-[var(--brand)] underline-offset-4 hover:underline',
      },
      size: {
        sm: 'h-7 px-2.5 text-[12px]',
        md: 'h-9 px-3.5',
        lg: 'h-10 px-5 text-sm',
        // Square icon sizes clear the 24x24 WCAG 2.2 (2.5.8) target minimum
        // even at `icon-sm`, where the glyph itself is only 16px.
        icon: 'size-9',
        'icon-sm': 'size-7',
      },
    },
    defaultVariants: { variant: 'glass', size: 'md' },
  },
);

export function Button({
  className,
  variant,
  size,
  asChild = false,
  ...props
}: ComponentProps<'button'> &
  VariantProps<typeof buttonVariants> & {
    /** Render the child element instead of a `<button>`, keeping the styling. */
    asChild?: boolean;
  }) {
  const Comp = asChild ? Slot : 'button';
  return <Comp data-slot="button" className={cn(buttonVariants({ variant, size }), className)} {...props} />;
}

export { buttonVariants };
