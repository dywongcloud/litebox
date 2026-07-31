import type { ComponentProps } from 'react';

import { cn } from '@/lib/utils';

/**
 * Glass surface primitive.
 *
 * `backdrop-blur` only produces the frosted effect when something is actually
 * behind the element to sample -- here that is the fixed ambient gradient
 * painted on `body::before`. On a flat background the blur is a no-op and the
 * card reads as plain translucency, which is why the ambient field and this
 * component ship together rather than as independent styling choices.
 */
export function Card({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      data-slot="card"
      className={cn(
        'relative rounded-[var(--radius-lg)] border border-[var(--glass-border)]',
        'bg-[var(--glass-bg)] backdrop-blur-[var(--glass-blur)]',
        'shadow-[var(--glass-shadow)]',
        // The inner top rim. A pseudo-element rather than an inset box-shadow
        // so it can be a gradient that fades out toward the card's edges,
        // matching how a real bevel catches light strongest at its centre.
        'before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px',
        'before:bg-[linear-gradient(90deg,transparent,var(--glass-highlight),transparent)]',
        'before:rounded-t-[var(--radius-lg)]',
        className,
      )}
      {...props}
    />
  );
}

export function CardHeader({ className, ...props }: ComponentProps<'div'>) {
  return <div data-slot="card-header" className={cn('flex flex-col gap-1 p-5 pb-3', className)} {...props} />;
}

export function CardTitle({ className, ...props }: ComponentProps<'h3'>) {
  return (
    <h3
      data-slot="card-title"
      className={cn('text-[15px] font-semibold tracking-[-0.01em] text-[var(--ink)]', className)}
      {...props}
    />
  );
}

export function CardDescription({ className, ...props }: ComponentProps<'p'>) {
  return (
    <p
      data-slot="card-description"
      className={cn('text-[13px] leading-relaxed text-[var(--muted)]', className)}
      {...props}
    />
  );
}

export function CardContent({ className, ...props }: ComponentProps<'div'>) {
  return <div data-slot="card-content" className={cn('p-5 pt-0', className)} {...props} />;
}

export function CardFooter({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-footer"
      className={cn('flex items-center gap-2 border-t border-[var(--line)] p-5 py-3', className)}
      {...props}
    />
  );
}
