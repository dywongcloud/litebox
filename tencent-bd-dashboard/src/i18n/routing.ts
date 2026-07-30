import { defineRouting } from 'next-intl/routing';

import { DEFAULT_LOCALE, LOCALES } from '@/domain/enums';

/**
 * Locale routing.
 *
 * Every path is locale-prefixed (`/en/...`, `/zh-Hans/...`, `/zh-Hant/...`),
 * including the default. An always-visible prefix keeps URLs unambiguous and
 * cacheable per locale, and removes the "which locale did this render as"
 * question from bug reports entirely.
 *
 * `zh-Hans` and `zh-Hant` are script subtags rather than region tags: the
 * distinction the PRD requires is the writing system, and `zh-CN`/`zh-TW` would
 * wrongly imply a jurisdiction.
 */
export const routing = defineRouting({
  locales: LOCALES,
  defaultLocale: DEFAULT_LOCALE,
  localePrefix: 'always',

  // Honour Accept-Language on first visit, then remember the explicit choice.
  localeDetection: true,
});
