import { hasLocale, NextIntlClientProvider } from 'next-intl';
import { setRequestLocale } from 'next-intl/server';
import { notFound } from 'next/navigation';
import type { Metadata } from 'next';

import { routing } from '@/i18n/routing';

import '../globals.css';

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
    <html lang={locale} dir="ltr">
      <body>
        <NextIntlClientProvider>{children}</NextIntlClientProvider>
      </body>
    </html>
  );
}
