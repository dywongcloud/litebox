import { hasLocale } from 'next-intl';
import { getRequestConfig } from 'next-intl/server';

import type { Locale } from '@/domain/enums';

import { routing } from './routing';

/**
 * Per-request i18n configuration.
 *
 * `requestLocale` comes from the URL segment, which is attacker-controllable,
 * so it is validated against the locale allowlist before being used to build a
 * module path. Interpolating it unchecked would be a path-traversal primitive
 * into the message directory.
 */
export default getRequestConfig(async ({ requestLocale }) => {
  const requested = await requestLocale;
  const locale: Locale = hasLocale(routing.locales, requested)
    ? requested
    : routing.defaultLocale;

  const messages = (await import(`./messages/${locale}.json`)).default;

  return {
    locale,
    messages,

    // Pin the formatter timezone so server and client renders agree; a
    // mismatch produces a hydration error on every date in the pipeline table.
    timeZone: 'UTC',

    formats: {
      dateTime: {
        short: { year: 'numeric', month: 'short', day: 'numeric' },
      },
    },

    onError(error) {
      // A missing message should show the key, not blank the page.
      if (process.env.NODE_ENV !== 'production') {
        console.warn('[i18n]', error.message);
      }
    },
  };
});
