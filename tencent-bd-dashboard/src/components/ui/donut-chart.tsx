'use client';

import { useMemo } from 'react';
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';

import { cn } from '@/lib/utils';
import { ChartTooltip } from '@/components/ui/chart-tooltip';
import { resolveChartColor } from '@/components/ui/chart-colors';
import type { ChartColor } from '@/components/ui/chart-colors';

/**
 * Tremor-style donut, on Recharts.
 *
 * A donut is only honest for a part-to-whole split with a handful of
 * categories -- which is what the priority and confidence mixes are. The
 * centre label carries the total so the ring does not have to be read
 * quantitatively; arc angles are poor at conveying precise magnitude, so the
 * number is what the reader actually takes the value from.
 */
export function DonutChart({
  data,
  index = 'name',
  category = 'value',
  colors,
  valueFormatter = (v) => String(v),
  centerLabel,
  centerValue,
  className,
  height = 200,
}: {
  data: Array<Record<string, unknown>>;
  index?: string;
  category?: string;
  colors?: ChartColor[];
  valueFormatter?: (value: number) => string;
  centerLabel?: string;
  centerValue?: string;
  className?: string;
  height?: number;
}) {
  const total = useMemo(
    () => data.reduce((sum, d) => sum + (Number(d[category]) || 0), 0),
    [data, category],
  );

  // An all-zero dataset renders as a zero-length ring, which Recharts draws as
  // a stray dot rather than nothing; show the empty state instead.
  if (total === 0) {
    return (
      <div
        data-slot="donut-chart"
        className={cn('grid place-items-center text-[13px] text-[var(--muted)]', className)}
        style={{ height }}
      >
        No data yet
      </div>
    );
  }

  return (
    <div data-slot="donut-chart" className={cn('relative', className)} style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey={category}
            nameKey={index}
            innerRadius="62%"
            outerRadius="92%"
            paddingAngle={2}
            strokeWidth={0}
            startAngle={90}
            endAngle={-270}
          >
            {data.map((entry, i) => (
              <Cell key={i} fill={resolveChartColor(colors?.[i], i)} />
            ))}
          </Pie>
          <Tooltip content={<ChartTooltip valueFormatter={valueFormatter} />} />
        </PieChart>
      </ResponsiveContainer>

      {/* Centred over the ring's hole. `pointer-events-none` so it never
          intercepts the hover that drives the tooltip. */}
      <div className="pointer-events-none absolute inset-0 grid place-content-center text-center">
        <div className="font-mono text-[22px] font-semibold leading-none tabular-nums text-[var(--ink)]">
          {centerValue ?? valueFormatter(total)}
        </div>
        {centerLabel ? (
          <div className="mt-1 text-[11px] font-semibold uppercase tracking-wide text-[var(--muted)]">{centerLabel}</div>
        ) : null}
      </div>
    </div>
  );
}

/** Swatch legend, kept out of the SVG so it can wrap with the layout. */
export function ChartLegend({
  items,
  colors,
  valueFormatter = (v) => String(v),
  className,
}: {
  items: Array<{ name: string; value: number }>;
  colors?: ChartColor[];
  valueFormatter?: (value: number) => string;
  className?: string;
}) {
  return (
    <ul data-slot="chart-legend" className={cn('flex flex-col gap-1.5', className)}>
      {items.map((item, i) => (
        <li key={item.name} className="flex items-center gap-2 text-[12px]">
          <span
            aria-hidden="true"
            className="size-2 shrink-0 rounded-[2px]"
            style={{ background: resolveChartColor(colors?.[i], i) }}
          />
          <span className="truncate text-[var(--ink-secondary)]">{item.name}</span>
          <span className="ml-auto font-[550] tabular-nums text-[var(--ink)]">{valueFormatter(item.value)}</span>
        </li>
      ))}
    </ul>
  );
}
