'use client';

import * as TooltipPrimitive from '@radix-ui/react-tooltip';
import type { ComponentProps } from 'react';

import { cn } from '@/lib/utils';

/**
 * Radix Tooltip for the truncated table cells.
 *
 * Those cells previously carried a `title` attribute, which has a ~1s browser
 * delay, no styling, no touch equivalent, and is not announced consistently by
 * screen readers. Radix renders a real element with `role="tooltip"` and wires
 * it to the trigger's `aria-describedby`.
 */
export const TooltipProvider = TooltipPrimitive.Provider;
export const Tooltip = TooltipPrimitive.Root;
export const TooltipTrigger = TooltipPrimitive.Trigger;

export function TooltipContent({
  className,
  sideOffset = 6,
  children,
  ...props
}: ComponentProps<typeof TooltipPrimitive.Content>) {
  return (
    <TooltipPrimitive.Portal>
      <TooltipPrimitive.Content
        data-slot="tooltip-content"
        sideOffset={sideOffset}
        className={cn(
          'z-[80] max-w-[min(28rem,calc(100vw-2rem))] rounded-[var(--radius-md)] px-2.5 py-1.5',
          'border border-[var(--glass-border)] bg-[var(--gray-900)]/92 backdrop-blur-md',
          'text-[12px] leading-relaxed text-[var(--gray-0)] shadow-[var(--glass-shadow)]',
          'data-[state=delayed-open]:animate-in data-[state=delayed-open]:fade-in-0 data-[state=delayed-open]:zoom-in-95',
          'data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95',
          className,
        )}
        {...props}
      >
        {children}
        <TooltipPrimitive.Arrow className="fill-[var(--gray-900)]/92" width={10} height={5} />
      </TooltipPrimitive.Content>
    </TooltipPrimitive.Portal>
  );
}

/**
 * Text that truncates to one line and reveals its full value on hover/focus.
 * `tabIndex={0}` is what makes it reachable without a pointer -- Radix wires
 * focus to the same open state as hover, so this is the whole keyboard story.
 */
export function TruncatedCell({ value, className }: { value: string; className?: string }) {
  const text = value.trim();
  if (!text) return <span className="text-[var(--gray-400)]">-</span>;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className={cn('block max-w-[22ch] truncate outline-none', 'focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]/55 focus-visible:rounded-sm', className)}>
          {text}
        </span>
      </TooltipTrigger>
      <TooltipContent>{text}</TooltipContent>
    </Tooltip>
  );
}
