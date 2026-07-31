import { createNavigation } from 'next-intl/navigation';

import { routing } from './routing';

/**
 * Locale-aware navigation primitives.
 *
 * Components import `Link` and `useRouter` from here rather than from `next` so
 * the active locale prefix is applied automatically -- a plain `next/link` would
 * drop the user back to the default locale on every internal navigation.
 */
export const { Link, redirect, usePathname, useRouter, getPathname } = createNavigation(routing);
