'use client';

import { useTranslations } from 'next-intl';

import { Card } from '@/components/ui/card';
import { BarChart, BarList, ProgressBar } from '@/components/ui/bar-chart';
import { ChartLegend, DonutChart } from '@/components/ui/donut-chart';
import type { ChartColor } from '@/components/ui/chart-colors';
import type { PortfolioAnalytics as Analytics } from '@/server/data/products';

/**
 * Catalog analytics strip.
 *
 * The page already showed these same figures as six bare counters; what the
 * counters could not show is *shape* -- that the knowledge ladder is
 * bottom-heavy, or which commercial categories carry the portfolio. Each panel
 * here is a distribution the raw numbers flatten away.
 *
 * A client component because Recharts measures its container to size the SVG,
 * which needs layout; the data itself is computed server-side in one table
 * scan and passed down, so nothing is fetched from the browser.
 */

// P1 is the most urgent tier, so the priority ring runs hot-to-cool rather
// than through the default categorical order.
const PRIORITY_COLORS: ChartColor[] = ['rose', 'amber', 'blue'];
// The ladder climbs toward "Can Sell", so colour progresses toward green.
const KNOWLEDGE_COLORS: ChartColor[] = ['slate', 'cyan', 'blue', 'emerald'];
const CONFIDENCE_COLORS: ChartColor[] = ['slate', 'amber', 'emerald'];

export function PortfolioAnalytics({ analytics }: { analytics: Analytics }) {
  const t = useTranslations('products');

  return (
    <div className="mb-4 grid gap-3 lg:grid-cols-[1.05fr_1.35fr_1.1fr]">
      <Card className="p-5">
        <PanelTitle>{t('chartPriorityTitle')}</PanelTitle>
        <DonutChart
          data={analytics.priorityMix}
          colors={PRIORITY_COLORS}
          centerValue={String(analytics.total)}
          centerLabel={t('chartPriorityCenter')}
          height={168}
        />
        <ChartLegend items={analytics.priorityMix} colors={PRIORITY_COLORS} className="mt-3" />
      </Card>

      {/* `flex-col` + a `flex-1` chart lets the middle panel absorb whatever
          height the tallest sibling sets, instead of leaving the grid's
          stretched cell half empty below a fixed-height chart. */}
      <Card className="flex flex-col p-5">
        <PanelTitle>{t('chartKnowledgeTitle')}</PanelTitle>
        <p className="mb-2 text-[12px] leading-relaxed text-[var(--muted)]">{t('chartKnowledgeHint')}</p>
        <BarChart
          data={analytics.knowledgeLadder}
          index="name"
          category="value"
          colors={KNOWLEDGE_COLORS}
          className="min-h-[150px] flex-1"
          height="100%"
        />
        <div className="mt-4 border-t border-[var(--line)] pt-4">
          <div className="flex items-center justify-between gap-3">
            <span className="text-[12px] text-[var(--muted)]">{t('chartCoverageLabel')}</span>
            <span className="font-mono text-[13px] font-semibold tabular-nums text-[var(--ink)]">
              {analytics.coverage}%
            </span>
          </div>
          <ProgressBar
            value={analytics.coverage}
            color={analytics.coverage >= 60 ? 'emerald' : analytics.coverage >= 25 ? 'amber' : 'rose'}
            className="mt-2"
          />
        </div>
      </Card>

      <Card className="flex flex-col p-5">
        <PanelTitle>{t('chartCategoryTitle')}</PanelTitle>
        <BarList data={analytics.topCategories} color="violet" className="mt-1" />
        <div className="mt-auto border-t border-[var(--line)] pt-4">
          <PanelTitle>{t('chartConfidenceTitle')}</PanelTitle>
          <ChartLegend items={analytics.confidenceMix} colors={CONFIDENCE_COLORS} />
        </div>
      </Card>
    </div>
  );
}

function PanelTitle({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.045em] text-[var(--muted)]">{children}</h3>
  );
}
