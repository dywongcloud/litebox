'use client';

import { cn } from '@/lib/utils';

/**
 * Shared tooltip surface for the Recharts-backed charts.
 *
 * Recharts hands the content renderer an untyped payload whose shape varies by
 * chart family, so the props are narrowed here rather than at each call site.
 * `active` can be true with an empty payload during the exit transition, which
 * is why both are checked before rendering.
 */
export interface ChartTooltipPayload {
  name?: string | number;
  value?: number | string;
  payload?: Record<string, unknown>;
  color?: string;
  fill?: string;
}

export function ChartTooltip({
  active,
  payload,
  label,
  valueFormatter = (v) => String(v),
}: {
  active?: boolean;
  payload?: ChartTooltipPayload[];
  label?: string | number;
  valueFormatter?: (value: number) => string;
}) {
  if (!active || !payload || payload.length === 0) return null;

  return (
    <div
      data-slot="chart-tooltip"
      className={cn(
        'rounded-[var(--radius-md)] border border-[var(--glass-border)]',
        'bg-[var(--glass-bg-strong)] px-3 py-2 shadow-[var(--glass-shadow)] backdrop-blur-xl',
      )}
    >
      {label !== undefined && label !== '' ? (
        <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-[var(--muted)]">{label}</div>
      ) : null}
      <div className="flex flex-col gap-1">
        {payload.map((entry, i) => (
          <div key={i} className="flex items-center gap-2 text-[12px]">
            <span
              aria-hidden="true"
              className="size-2 shrink-0 rounded-[2px]"
              style={{ background: entry.color ?? entry.fill ?? 'currentColor' }}
            />
            <span className="text-[var(--ink-secondary)]">{entry.name}</span>
            <span className="ml-auto font-[550] tabular-nums text-[var(--ink)]">
              {typeof entry.value === 'number' ? valueFormatter(entry.value) : entry.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
