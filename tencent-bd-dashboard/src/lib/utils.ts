import { clsx } from 'clsx';
import type { ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Conditional class names, with later Tailwind utilities beating earlier ones.
 *
 * `clsx` flattens the conditional forms; `twMerge` then resolves same-property
 * conflicts by keeping the last one. Without the merge step a caller's
 * `className="px-6"` would sit alongside a component's built-in `px-4` and the
 * winner would be whichever CSS rule the cascade happened to order last --
 * which for two utilities of equal specificity is source order in the compiled
 * stylesheet, not the order they appear in the attribute.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
