'use client';

import * as SelectPrimitive from '@radix-ui/react-select';
import { Check, ChevronDown, ChevronUp } from 'lucide-react';
import type { ComponentProps } from 'react';

import { cn } from '@/lib/utils';

/**
 * Radix Select, for the long enum lists inside dialogs.
 *
 * A native `<select>` renders its popup with the OS widget, which cannot be
 * styled and looks conspicuously foreign against a glass surface. This
 * renders its own listbox instead -- at the cost of no longer being a real
 * form control, so it is deliberately *not* the default: filter bars and the
 * board's inline status control keep `NativeSelect` from `input.tsx` so they
 * still submit without JavaScript.
 */
export const Select = SelectPrimitive.Root;
export const SelectGroup = SelectPrimitive.Group;
export const SelectValue = SelectPrimitive.Value;

export function SelectTrigger({ className, children, ...props }: ComponentProps<typeof SelectPrimitive.Trigger>) {
  return (
    <SelectPrimitive.Trigger
      data-slot="select-trigger"
      className={cn(
        'flex h-9 w-full items-center justify-between gap-2 rounded-[var(--radius-md)]',
        'border border-[var(--line-strong)] bg-[var(--panel)]/70 px-3 backdrop-blur-sm',
        'text-[13px] text-[var(--ink)] transition-[border-color,box-shadow] duration-150',
        'data-[placeholder]:text-[var(--gray-400)]',
        'hover:border-[var(--gray-400)]',
        'focus-visible:outline-none focus-visible:border-[var(--brand)] focus-visible:ring-[3px] focus-visible:ring-[var(--focus-ring)]/18',
        'disabled:cursor-not-allowed disabled:opacity-55',
        '[&>span]:truncate',
        className,
      )}
      {...props}
    >
      {children}
      <SelectPrimitive.Icon asChild>
        <ChevronDown className="size-4 shrink-0 text-[var(--muted)]" />
      </SelectPrimitive.Icon>
    </SelectPrimitive.Trigger>
  );
}

export function SelectContent({
  className,
  children,
  position = 'popper',
  ...props
}: ComponentProps<typeof SelectPrimitive.Content>) {
  return (
    <SelectPrimitive.Portal>
      <SelectPrimitive.Content
        data-slot="select-content"
        position={position}
        className={cn(
          'relative z-[70] max-h-[min(24rem,var(--radix-select-content-available-height))] min-w-[8rem]',
          'overflow-hidden rounded-[var(--radius-md)] border border-[var(--glass-border)]',
          'bg-[var(--glass-bg-strong)] backdrop-blur-[22px] shadow-[var(--glass-shadow)]',
          'data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95',
          'data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95',
          position === 'popper' && 'data-[side=bottom]:translate-y-1 data-[side=top]:-translate-y-1',
          className,
        )}
        {...props}
      >
        <SelectPrimitive.ScrollUpButton className="flex h-6 items-center justify-center text-[var(--muted)]">
          <ChevronUp className="size-3.5" />
        </SelectPrimitive.ScrollUpButton>
        <SelectPrimitive.Viewport
          className={cn('p-1', position === 'popper' && 'w-full min-w-[var(--radix-select-trigger-width)]')}
        >
          {children}
        </SelectPrimitive.Viewport>
        <SelectPrimitive.ScrollDownButton className="flex h-6 items-center justify-center text-[var(--muted)]">
          <ChevronDown className="size-3.5" />
        </SelectPrimitive.ScrollDownButton>
      </SelectPrimitive.Content>
    </SelectPrimitive.Portal>
  );
}

export function SelectItem({ className, children, ...props }: ComponentProps<typeof SelectPrimitive.Item>) {
  return (
    <SelectPrimitive.Item
      data-slot="select-item"
      className={cn(
        'relative flex w-full cursor-pointer select-none items-center gap-2 rounded-[var(--radius-sm)]',
        'py-1.5 pl-2.5 pr-8 text-[13px] text-[var(--ink)] outline-none',
        'data-[highlighted]:bg-[var(--brand-50)] data-[highlighted]:text-[var(--brand-700)]',
        'data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
        className,
      )}
      {...props}
    >
      <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
      <span className="absolute right-2.5 flex size-3.5 items-center justify-center">
        <SelectPrimitive.ItemIndicator>
          <Check className="size-3.5 text-[var(--brand)]" />
        </SelectPrimitive.ItemIndicator>
      </span>
    </SelectPrimitive.Item>
  );
}

export function SelectLabel({ className, ...props }: ComponentProps<typeof SelectPrimitive.Label>) {
  return (
    <SelectPrimitive.Label
      data-slot="select-label"
      className={cn('px-2.5 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-[var(--muted)]', className)}
      {...props}
    />
  );
}

export function SelectSeparator({ className, ...props }: ComponentProps<typeof SelectPrimitive.Separator>) {
  return <SelectPrimitive.Separator data-slot="select-separator" className={cn('-mx-1 my-1 h-px bg-[var(--line)]', className)} {...props} />;
}
