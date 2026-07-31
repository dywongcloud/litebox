import { GeistMono } from 'geist/font/mono';
import { GeistSans } from 'geist/font/sans';
import { hasLocale, NextIntlClientProvider } from 'next-intl';
import { setRequestLocale } from 'next-intl/server';
import { notFound } from 'next/navigation';
import type { Metadata } from 'next';

import { routing } from '@/i18n/routing';

import '../globals.css';

/**
 * Typography.
 *
 * Geist (Vercel's OFL-licensed variable family) rather than a second
 * hand-picked display face: this is a data-dense operating console, not a
 * marketing page, and the engineered-SaaS look the redesign is going for
 * (Linear/Stripe/Vercel-style) comes from disciplined weight and size
 * variation within one excellent sans, not from mixing families. Geist Mono
 * carries tabular data -- KPI numbers, scores, dates, ids -- so columns of
 * digits actually align.
 *
 * Neither face covers CJK glyphs (Geist is Latin-only), so Chinese text falls
 * through to the platform's own CJK font via the stack in `globals.css`
 * (PingFang SC / Microsoft YaHei / Noto Sans CJK). Shipping a CJK webfont was
 * considered and rejected: even aggressively subset, Chinese webfonts run into
 * several megabytes because the character set itself is thousands of glyphs,
 * and every mainstream Chinese-facing product (WeChat, Alibaba, Tencent's own
 * properties) relies on the system CJK font for exactly this reason rather
 * than shipping one.
 */

/**
 * Root layout for every locale.
 *
 * There is no `app/layout.tsx` above this one: with `localePrefix: 'always'`
 * every real route lives under `[locale]`, so this is the outermost layout and
 * is the one that owns `<html>`/`<body>` -- the App Router requires exactly one
 * such layout, and next-intl's own reference setup places it here rather than
 * duplicating a locale-less shell above it.
 */

export function generateStaticParams() {
  return routing.locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: 'Tencent Cloud NA BD Operating System',
  description: 'Solution selling, account pipeline and BD execution workspace.',
  robots: { index: false, follow: false },
};

export default async function LocaleLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  if (!hasLocale(routing.locales, locale)) notFound();

  // Enables static rendering for this request tree; without it every page in
  // this layout would be forced dynamic purely by locale resolution.
  setRequestLocale(locale);

  return (
    <html lang={locale} dir="ltr" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body>
        <NextIntlClientProvider>{children}</NextIntlClientProvider>
      </body>
    </html>
  );
}
