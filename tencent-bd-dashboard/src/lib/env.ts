import 'server-only';

import { z } from 'zod';

/**
 * Typed, validated process environment.
 *
 * Parsed once at module load so a misconfigured deployment fails immediately
 * and loudly instead of degrading into an insecure default at request time.
 * Importing `server-only` guarantees a bundler error if this file is ever
 * pulled into a client component, which would leak the secrets below.
 */

const isProduction = process.env.NODE_ENV === 'production';

const seconds = (fallback: number) =>
  z
    .string()
    .optional()
    .transform((v) => (v === undefined || v === '' ? fallback : Number(v)))
    .pipe(z.number().int().positive().max(60 * 60 * 24 * 30));

const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),

    // A short secret would make session and CSRF token forgery tractable.
    APP_SECRET: z
      .string()
      .min(32, 'APP_SECRET must be at least 32 characters of high-entropy material'),

    APP_ORIGIN: z.string().url().optional(),

    DATABASE_PATH: z.string().min(1).default('./data/bd-os.db'),

    BOOTSTRAP_ADMIN_EMAIL: z.string().email().optional(),
    BOOTSTRAP_ADMIN_PASSWORD: z.string().optional(),

    TENCENTCLOUD_SECRET_ID: z.string().optional(),
    TENCENTCLOUD_SECRET_KEY: z.string().optional(),
    TENCENTCLOUD_REGION: z.string().default('ap-singapore'),
    TENCENTCLOUD_TMT_PROJECT_ID: z
      .string()
      .optional()
      .transform((v) => (v === undefined || v === '' ? 0 : Number(v)))
      .pipe(z.number().int().nonnegative()),

    SESSION_IDLE_TTL_SECONDS: seconds(60 * 60),
    SESSION_ABSOLUTE_TTL_SECONDS: seconds(60 * 60 * 12),
    LOGIN_MAX_ATTEMPTS: seconds(5),
    LOGIN_LOCKOUT_SECONDS: seconds(15 * 60),
  })
  .superRefine((value, ctx) => {
    // In production there is no safe guess for the canonical origin, and the
    // same-origin check on mutations depends on knowing it exactly.
    if (isProduction && !value.APP_ORIGIN) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['APP_ORIGIN'],
        message: 'APP_ORIGIN is required in production for same-origin enforcement',
      });
    }

    // Half-configured credentials would silently sign requests with an empty
    // key; require both halves or neither.
    const hasId = Boolean(value.TENCENTCLOUD_SECRET_ID);
    const hasKey = Boolean(value.TENCENTCLOUD_SECRET_KEY);
    if (hasId !== hasKey) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['TENCENTCLOUD_SECRET_KEY'],
        message:
          'TENCENTCLOUD_SECRET_ID and TENCENTCLOUD_SECRET_KEY must be set together, or both left empty',
      });
    }

    if (value.SESSION_IDLE_TTL_SECONDS > value.SESSION_ABSOLUTE_TTL_SECONDS) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['SESSION_IDLE_TTL_SECONDS'],
        message: 'Idle TTL cannot exceed the absolute session lifetime',
      });
    }
  });

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  const detail = parsed.error.issues
    .map((issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
    .join('\n');
  throw new Error(`Invalid environment configuration:\n${detail}`);
}

export const env = parsed.data;

/** True when live Tencent Cloud API calls are configured and permitted. */
export const hasTencentCredentials =
  Boolean(env.TENCENTCLOUD_SECRET_ID) && Boolean(env.TENCENTCLOUD_SECRET_KEY);

export const isProd = isProduction;
