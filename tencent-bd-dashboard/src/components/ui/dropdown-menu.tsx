'use client';

import * as DropdownMenuPrimitive from '@radix-ui/react-dropdown-menu';
import type { ComponentProps } from 'react';

import { cn } from '@/lib/utils';

/**
 * Row-action menu.
 *
 * The catalog table previously rendered four or five inline buttons per row,
 * which at 40 rows is ~200 competing targets and the widest column on the
 * page. Collapsing them behind one trigger returns that width to the data and
 * gives the actions readable labels instead of abbreviations.
 */
export const DropdownMenu = DropdownMenuPrimitive.Root;
export const DropdownMenuTrigger = DropdownMenuPrimitive.Trigger;
export const DropdownMenuGroup = DropdownMenuPrimitive.Group;

export function DropdownMenuContent({
  className,
  sideOffset = 6,
  align = 'end',
  ...props
}: ComponentProps<typeof DropdownMenuPrimitive.Content>) {
  return (
    <DropdownMenuPrimitive.Portal>
      <DropdownMenuPrimitive.Content
        data-slot="dropdown-menu-content"
        sideOffset={sideOffset}
        align={align}
        className={cn(
          'z-[70] min-w-[11rem] overflow-hidden rounded-[var(--radius-md)] p-1',
          'border border-[var(--glass-border)] bg-[var(--glass-bg-strong)] backdrop-blur-[22px]',
          'shadow-[var(--glass-shadow)]',
          'data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95',
          'data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95',
          className,
        )}
        {...props}
      />
    </DropdownMenuPrimitive.Portal>
  );
}

export function DropdownMenuItem({
  className,
  tone = 'default',
  ...props
}: ComponentProps<typeof DropdownMenuPrimitive.Item> & { tone?: 'default' | 'danger' }) {
  return (
    <DropdownMenuPrimitive.Item
      data-slot="dropdown-menu-item"
      className={cn(
        'relative flex cursor-pointer select-none items-center gap-2 rounded-[var(--radius-sm)]',
        'px-2.5 py-1.5 text-[13px] outline-none transition-colors',
        "[&_svg]:size-3.5 [&_svg]:shrink-0 [&_svg]:text-[var(--muted)]",
        tone === 'danger'
          ? 'text-[var(--danger)] data-[highlighted]:bg-[var(--danger-bg)] [&_svg]:text-[var(--danger)]'
          : 'text-[var(--ink)] data-[highlighted]:bg-[var(--brand-50)] data-[highlighted]:text-[var(--brand-700)] data-[highlighted]:[&_svg]:text-[var(--brand-600)]',
        'data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
        className,
      )}
      {...props}
    />
  );
}

export function DropdownMenuLabel({ className, ...props }: ComponentProps<typeof DropdownMenuPrimitive.Label>) {
  return (
    <DropdownMenuPrimitive.Label
      data-slot="dropdown-menu-label"
      className={cn('px-2.5 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-[var(--muted)]', className)}
      {...props}
    />
  );
}

export function DropdownMenuSeparator({ className, ...props }: ComponentProps<typeof DropdownMenuPrimitive.Separator>) {
  return (
    <DropdownMenuPrimitive.Separator
      data-slot="dropdown-menu-separator"
      className={cn('-mx-1 my-1 h-px bg-[var(--line)]', className)}
      {...props}
    />
  );
}
