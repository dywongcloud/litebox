import type messages from '@/i18n/messages/en.json';

/**
 * Types every `useTranslations`/`getTranslations` call against the shape of
 * the English message catalog -- the source of truth other locales are kept
 * in sync with. A typo'd or removed key becomes a compile error instead of a
 * silent fallback to the raw key string at runtime.
 */
declare module 'next-intl' {
  interface AppConfig {
    Messages: typeof messages;
  }
}
