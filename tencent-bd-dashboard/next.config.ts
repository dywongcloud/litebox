import type { NextConfig } from 'next';
import createNextIntlPlugin from 'next-intl/plugin';

const withNextIntl = createNextIntlPlugin('./src/i18n/request.ts');

const nextConfig: NextConfig = {
  reactStrictMode: true,

  // Never leak framework version or stack details to clients.
  poweredByHeader: false,

  // Fail the production build on type errors rather than shipping them.
  // (Next.js 16 dropped the built-in `next lint` / `eslint` build integration;
  // static analysis here is `npm run typecheck`, run in CI alongside this.)
  typescript: { ignoreBuildErrors: false },

  // better-sqlite3 is a native addon: keep it external to the server bundle.
  serverExternalPackages: ['better-sqlite3'],

  experimental: {
    // Server Actions are the only mutation surface; bound the request body so a
    // single action call cannot be used to exhaust memory.
    serverActions: { bodySizeLimit: '1mb' },
  },
};

export default withNextIntl(nextConfig);
