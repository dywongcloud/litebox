import { defineConfig } from 'drizzle-kit';

/**
 * Drizzle Kit is used to generate SQL migrations from `src/db/schema.ts`.
 * Runtime migration is applied by `src/db/migrate.ts`, not by this config.
 */
export default defineConfig({
  dialect: 'sqlite',
  schema: './src/db/schema.ts',
  out: './drizzle',
  dbCredentials: {
    url: process.env.DATABASE_PATH ?? './data/bd-os.db',
  },
  strict: true,
  verbose: true,
});
