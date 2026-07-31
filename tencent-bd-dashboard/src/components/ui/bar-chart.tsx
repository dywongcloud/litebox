'use client';

import { Bar, BarChart as RechartsBarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { cn } from '@/lib/utils';
import { ChartTooltip } from '@/components/ui/chart-tooltip';
import { resolveChartColor } from '@/components/ui/chart-colors';
import type { ChartColor } from '@/components/ui/chart-colors';

const AXIS_TICK = { fill: 'var(--muted)', fontSize: 11 };

/**
 * Tremor-style vertical bar chart.
 *
 * Grid lines are horizontal only: vertical rules between categorical bars add
 * ink without adding readability, since the bars themselves already delimit
 * the categories. The y-axis is hidden by default for the same reason -- with
 * a tooltip and few enough bars, the axis is redundant scaffolding.
 */
export function BarChart({
  data,
  index,
  category,
  color,
  colors,
  valueFormatter = (v) => String(v),
  height = 200,
  showYAxis = false,
  className,
}: {
  data: Array<Record<string, unknown>>;
  index: string;
  category: string;
  color?: ChartColor;
  /** Per-bar colors, when each category carries its own meaning. */
  colors?: ChartColor[];
  valueFormatter?: (value: number) => string;
  /** Number for a fixed pixel height, or `'100%'` to fill a flex parent. */
  height?: number | string;
  showYAxis?: boolean;
  className?: string;
}) {
  const empty = data.every((d) => !Number(d[category]));
  if (data.length === 0 || empty) {
    return (
      <div
        data-slot="bar-chart"
        className={cn('grid place-items-center text-[13px] text-[var(--muted)]', className)}
        style={{ height }}
      >
        No data yet
      </div>
    );
  }

  return (
    <div data-slot="bar-chart" className={cn(className)} style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <RechartsBarChart data={data} margin={{ top: 6, right: 4, bottom: 0, left: showYAxis ? 0 : -28 }}>
          <CartesianGrid stroke="var(--line)" strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey={index}
            tick={AXIS_TICK}
            tickLine={false}
            axisLine={false}
            interval={0}
            // Long enum labels ("Can Explain", "Hypothesis") collide at narrow
            // widths; truncating keeps them on one line and the tooltip still
            // carries the full value.
            tickFormatter={(v: string) => (v.length > 12 ? `${v.slice(0, 11)}…` : v)}
          />
          <YAxis tick={AXIS_TICK} tickLine={false} axisLine={false} width={showYAxis ? 32 : 0} allowDecimals={false} />
          <Tooltip
            content={<ChartTooltip valueFormatter={valueFormatter} />}
            cursor={{ fill: 'color-mix(in srgb, var(--ink) 6%, transparent)' }}
          />
          <Bar dataKey={category} radius={[5, 5, 0, 0]} maxBarSize={56}>
            {data.map((_, i) => (
              <Cell key={i} fill={colors ? resolveChartColor(colors[i], i) : resolveChartColor(color, 0)} />
            ))}
          </Bar>
        </RechartsBarChart>
      </ResponsiveContainer>
    </div>
  );
}

/**
 * Horizontal bar list -- Tremor's `BarList`.
 *
 * Deliberately plain DOM rather than Recharts: for a ranked list of labelled
 * magnitudes this is a handful of divs, and keeping it out of the charting
 * library means the labels stay real selectable text that reflows with the
 * layout instead of SVG glyphs that clip.
 */
export function BarList({
  data,
  color = 'blue',
  valueFormatter = (v) => String(v),
  className,
}: {
  data: Array<{ name: string; value: number }>;
  color?: ChartColor;
  valueFormatter?: (value: number) => string;
  className?: string;
}) {
  const max = Math.max(...data.map((d) => d.value), 1);
  const fill = resolveChartColor(color, 0);

  return (
    <div data-slot="bar-list" className={cn('flex flex-col gap-2', className)}>
      {data.map((item) => (
        <div key={item.name} className="grid grid-cols-[1fr_auto] items-center gap-3">
          <div className="relative h-7 overflow-hidden rounded-[var(--radius-sm)]">
            <div
              className="absolute inset-y-0 left-0 rounded-[var(--radius-sm)] transition-[width] duration-500 ease-[var(--ease-out)]"
              style={{ width: `${Math.max((item.value / max) * 100, 2)}%`, background: fill, opacity: 0.22 }}
            />
            <span className="relative flex h-full items-center truncate px-2 text-[12px] text-[var(--ink)]">
              {item.name}
            </span>
          </div>
          <span className="text-[12px] font-[550] tabular-nums text-[var(--ink-secondary)]">
            {valueFormatter(item.value)}
          </span>
        </div>
      ))}
    </div>
  );
}

/** Single-value progress meter, for a percentage with a known ceiling. */
export function ProgressBar({
  value,
  max = 100,
  color = 'blue',
  className,
}: {
  value: number;
  max?: number;
  color?: ChartColor;
  className?: string;
}) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));
  return (
    <div
      data-slot="progress-bar"
      role="progressbar"
      aria-valuenow={Math.round(value)}
      aria-valuemin={0}
      aria-valuemax={max}
      className={cn('h-2 w-full overflow-hidden rounded-full bg-[var(--bg-subtle)]', className)}
    >
      <div
        className="h-full rounded-full transition-[width] duration-500 ease-[var(--ease-out)]"
        style={{ width: `${pct}%`, background: resolveChartColor(color, 0) }}
      />
    </div>
  );
}
