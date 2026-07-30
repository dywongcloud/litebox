# Tencent Cloud NA BD Operating System

A secure Next.js + TypeScript port of the original single-file HTML BD
dashboard, rebuilt around the four requirements in the PRD:

1. **Account Pipelines** — stored in a SQLite database (not `localStorage`).
2. **Service Catalog Search / 产品情报库** — consumes an upstream Tencent
   Cloud product API.
3. **Locales / Translation** — safe auto-translation between English and
   Chinese (Simplified and Traditional).
4. **Typesafe schema** — a single Drizzle schema, inferred TypeScript types,
   and Zod validation at every input boundary.

It keeps all six tabs from the original dashboard (Service Catalog, Account
Pipeline, Development SOP, Next-Step Board, Entry Playbooks, Weekly CEO
Review) plus authentication, role-based access control, and an admin panel —
none of which the source HTML file had, since it ran entirely client-side
with no backend.

## Quick start

```bash
npm install
cp .env.example .env.local   # then fill in APP_SECRET and bootstrap admin credentials
npm run db:seed              # migrates the DB and loads the 181-product corpus
npm run dev                  # http://localhost:3000
```

Generate `APP_SECRET`:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

Sign in with the `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` you set
in `.env.local` before running `db:seed` (the password must satisfy the
policy — 12+ characters with upper, lower, digit, and symbol).

## Scripts

| Command | Purpose |
|---|---|
| `npm run dev` | Development server |
| `npm run build` | Production build (fails on type errors) |
| `npm start` | Run the production build |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run db:migrate` | Apply pending Drizzle migrations |
| `npm run db:seed` | Migrate + load the initial corpus + create the bootstrap admin |
| `npm run db:reset` | Reload the initial corpus (users/sessions/audit log untouched) |

## Architecture

```
src/
  domain/          Enum vocabularies + Zod schemas (the "typesafe schema" layer)
  db/               Drizzle schema, SQLite client, migrations, seed corpus
  lib/
    auth/           Sessions, RBAC, the requireRead/requireMutation guard, password policy
    security/       scrypt hashing, CSRF, rate limiting, audit log, request context
    env.ts          Validated environment configuration
  i18n/             next-intl routing + message catalogs (en, zh-Hans, zh-Hant)
  server/
    data/           Query layer (one module per entity)
    actions/        Server Actions -- the only mutation surface
    tencent/        TC3-HMAC-SHA256 signer + Tencent Cloud API clients
    catalog/        Upstream product-catalog sync
    translation/     Script conversion (zh-Hans <-> zh-Hant) + machine translation (en <-> zh)
  components/       Shared client/server UI primitives
  app/[locale]/     Routes (App Router, locale-prefixed throughout)
```

### Security model

- **Auth**: opaque server-side sessions (random token, hashed at rest),
  scrypt password hashing, account lockout after repeated failures,
  idle + absolute session timeouts, session revocation on password change.
- **CSRF**: signed double-submit tokens bound to the session id, minted once
  at login (Next.js forbids writing cookies during a page render — only
  Server Actions/Route Handlers may — so the token is never re-minted on a
  GET).
- **Origin checks**: every mutation independently verifies the `Origin`
  header against an allowlist, on top of the CSRF token.
- **Rate limiting**: persisted, fixed-window, per-bucket (login, mutation,
  translation, catalog sync, export), so it survives a restart and holds
  across workers.
- **RBAC**: three roles (`admin`, `editor`, `viewer`) mapped to named
  permissions, checked identically at the Server Action layer for every
  request — client-side tab hiding is a convenience, never the boundary.
- **Audit log**: append-only record of every auth event and business
  mutation.
- **Headers**: a per-request CSP nonce, `X-Frame-Options`,
  `Permissions-Policy` (fully denied), `Strict-Transport-Security`, and
  `Cross-Origin-Opener/Resource-Policy`, all set in `src/proxy.ts`
  (Next.js 16 renamed the `middleware.ts` convention to `proxy.ts`).

**Deployment note**: `Strict-Transport-Security` is sent whenever
`NODE_ENV=production`. Serve this behind real TLS (terminate HTTPS in front
of it) — testing the production build over plain HTTP in a browser that
caches HSTS for `localhost` will cause the browser to force-upgrade
subsequent requests to HTTPS and fail to connect. `npm run dev` does not set
this header.

### Data model

SQLite via `better-sqlite3` + Drizzle ORM. Every enum column is typed against
the closed vocabularies in `src/domain/enums.ts` and validated at every
write boundary with the matching Zod schema in `src/domain/schemas.ts` — the
same source of truth Drizzle's inferred `Product`/`Account`/etc. types come
from, so the persisted shape, the compile-time type, and the runtime
validator cannot drift from one another.

Evidence rows (`product_evidence`) are normalised out of the product row
into their own table, so the Evidence Studio's "which claims may I actually
state to a customer" question is a query, not a document scan.

### Upstream Tencent Cloud integration

Two live API integrations, both behind `TENCENTCLOUD_SECRET_ID`/
`TENCENTCLOUD_SECRET_KEY` (unset by default — the app works fully on the
bundled local corpus without them):

- **Catalog sync** (`src/server/catalog/sync.ts`): calls the Billing API's
  `DescribeProducts` action (the one stable, generally-available Tencent
  Cloud API that returns a product code/name catalog — there is no public
  "marketing catalog" API). A sync only attaches an upstream code to an
  existing product by name match, or creates a minimal stub row; it never
  overwrites BD intelligence a rep has already written.
- **Machine translation** (`src/server/translation/service.ts`): calls the
  TMT `TextTranslate` action for any `en <-> zh` pair. Simplified/Traditional
  conversion never calls this API — it is done locally and deterministically
  with `opencc-js`.

Both go through `src/server/tencent/signer.ts`, a from-scratch implementation
of Tencent Cloud's TC3-HMAC-SHA256 request signature.

### Translation safety

The Evidence Studio's whole discipline — never state an unsupported claim —
extends to translation: every stored translation carries an `origin`
(`human` / `machine` / `script-conversion`) and a `status`
(`draft` / `needs-review` / `approved`), plus a hash of the source text it
was produced from. A source edit invalidates the translation instead of
silently serving it stale, and the UI marks machine output as unreviewed
until an admin approves it in **Administration → Translations**.

## Known scope trims

Built to be genuinely complete against the PRD and a faithful, secure port
of all six original tabs — a few original features were deliberately left
out or simplified given the size of the source app, noted here rather than
silently dropped:

- **Bulk JSON import** (the original's "导入更新" button): export is fully
  implemented; a validated bulk-import counterpart was scoped out as
  lower-value relative to its implementation cost (it would need its own
  comprehensive per-row Zod schema mirroring every entity). `db:reset`
  covers "restore the known-good corpus."
- **CSV export**: only the whole-database JSON export is implemented.
- **Kanban drag-and-drop**: the Next-Step Board moves a card between columns
  via a "move to" select rather than pointer drag-and-drop — same data model
  (`position` column), simpler and keyboard-accessible; a drag interaction
  could be layered on later without a schema change.
- **ESLint**: Next.js 16 removed the built-in `next lint`/`eslint` build
  integration; static checking here is `npm run typecheck` (strict mode,
  `noUncheckedIndexedAccess`) rather than a separate lint config.

## Environment variables

See `.env.example` for the full list with descriptions. Only `APP_SECRET` is
required to start the app; everything else has a safe default or degrades
gracefully (no Tencent credentials → local corpus + script-conversion-only
translation; no `APP_ORIGIN` in development → localhost is allowed).
