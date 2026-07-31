import { applySeedCorpus } from './seed-corpus';

/**
 * CLI wrapper around `applySeedCorpus` for local development
 * (`npm run db:reset`). Users, sessions and the audit log are untouched -- see
 * `applySeedCorpus` for why. The in-app "restore initial version" admin action
 * calls the same function; this script exists for the case where the app
 * itself is not running.
 */
const counts = applySeedCorpus();
console.log(
  `[reset] corpus reloaded: ${counts.products} products, ${counts.accounts} accounts, ${counts.todos} todos`,
);
