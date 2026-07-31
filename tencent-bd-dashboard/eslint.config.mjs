import nextConfig from 'eslint-config-next';

/** @type {import('eslint').Linter.Config[]} */
const config = [
  ...nextConfig,
  {
    rules: {
      // The codebase's own convention for a deliberately-omitted hook
      // dependency (a stable context callback, a run-once-per-id effect) is
      // an inline `eslint-disable-next-line` with a comment explaining why,
      // not a blanket rule change -- keep the rule on so a *new* missing
      // dependency still gets caught.
      'react-hooks/exhaustive-deps': 'warn',
    },
  },
  {
    ignores: ['src/db/seed-data/**'],
  },
];

export default config;
