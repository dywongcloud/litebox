'use client';

import { useTransition } from 'react';
import { useLocale, useTranslations } from 'next-intl';

import { LOCALES, type Locale } from '@/domain/enums';
import { usePathname, useRouter } from '@/i18n/navigation';

const LOCALE_LABELS: Record<Locale, string> = {
  en: 'English',
  'zh-Hans': '简体中文',
  'zh-Hant': '繁體中文',
};

export function LocaleSwitcher() {
  const t = useTranslations('app');
  const locale = useLocale();
  const pathname = usePathname();
  const router = useRouter();
  const [isPending, startTransition] = useTransition();

  return (
    <label className="row" style={{ color: 'inherit' }}>
      <span className="visually-hidden">{t('language')}</span>
      <select
        aria-label={t('language')}
        value={locale}
        disabled={isPending}
        onChange={(event) => {
          const nextLocale = event.target.value as Locale;
          startTransition(() => {
            router.replace(pathname, { locale: nextLocale });
          });
        }}
        style={{ width: 'auto', background: 'transparent', color: 'inherit', borderColor: '#ffffff33' }}
      >
        {LOCALES.map((code) => (
          <option key={code} value={code} style={{ color: '#111' }}>
            {LOCALE_LABELS[code]}
          </option>
        ))}
      </select>
    </label>
  );
}
