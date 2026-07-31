/**
 * Chart palette, shared by every Tremor chart component.
 *
 * Tremor Raw's own components key colors by a semantic name (`blue`, `emerald`,
 * ...) rather than taking raw hex, so a chart's call site never hardcodes a
 * value and the whole set can be retuned here. These resolve to literal hex
 * rather than `var(--brand-500)` because Recharts passes the value into SVG
 * `fill`/`stroke` attributes and interpolates it during animation -- a
 * `var()` reference survives the attribute but not the interpolation, which
 * makes bars flash to black mid-transition.
 *
 * Hues are spaced far enough apart to stay distinguishable under the common
 * forms of color-vision deficiency: the ordered set avoids adjacent red/green
 * pairs, which is where deuteranopia collapses categories together.
 */
export type ChartColor = 'blue' | 'violet' | 'emerald' | 'amber' | 'rose' | 'cyan' | 'slate';

export const CHART_COLORS: Record<ChartColor, string> = {
  blue: '#3b82f6',
  violet: '#8b5cf6',
  emerald: '#10b981',
  amber: '#f59e0b',
  rose: '#f43f5e',
  cyan: '#06b6d4',
  slate: '#94a3b8',
};

/** Default assignment order when a chart is given more series than colors. */
export const CHART_COLOR_ORDER: ChartColor[] = ['blue', 'violet', 'emerald', 'amber', 'cyan', 'rose', 'slate'];

export function resolveChartColor(color: ChartColor | undefined, index: number): string {
  if (color && CHART_COLORS[color]) return CHART_COLORS[color];
  return CHART_COLORS[CHART_COLOR_ORDER[index % CHART_COLOR_ORDER.length]!];
}

/** Compact integer formatting, the default for count-based axes and labels. */
export function formatCount(value: number): string {
  return new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(value);
}
