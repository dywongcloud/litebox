import { relations, sql } from 'drizzle-orm';
import {
  index,
  integer,
  primaryKey,
  sqliteTable,
  text,
  uniqueIndex,
} from 'drizzle-orm/sqlite-core';

import type {
  AccountFit,
  AccountSize,
  AccountStage,
  CanSay,
  CommercialCategory,
  ConfidenceLevel,
  EvidenceConfidence,
  EvidenceLevel,
  KnowledgeLevel,
  Locale,
  Priority,
  ProductStatus,
  SellMode,
  TodoOwner,
  TodoPriority,
  TodoStatus,
  TranslationSource,
  TranslationStatus,
  UserRole,
} from '@/domain/enums';

/**
 * SQLite schema for the BD operating system.
 *
 * Two conventions run through every table:
 *
 *   1. Enum-valued columns are `text().$type<T>()` where `T` comes from
 *      `@/domain/enums`. SQLite has no native enum, so the closed set is
 *      enforced by Zod at the write boundary and by TypeScript at every read.
 *      A value that reaches these columns has passed both.
 *
 *   2. Free-text columns are `notNull().default('')` rather than nullable.
 *      The source application treated a missing field and an empty field
 *      identically; collapsing them removes a whole class of null-handling
 *      branches from the render path without losing information.
 *
 * Timestamps are stored as integer epoch milliseconds and surface as `Date`.
 */

const now = sql`(unixepoch() * 1000)`;

/** Columns every mutable business record carries, for audit reconstruction. */
const stamps = {
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull().default(now),
};

// ---------------------------------------------------------------------------
// Identity and access
// ---------------------------------------------------------------------------

export const users = sqliteTable(
  'users',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),

    /** Stored lowercased and trimmed; the unique index below is the real guard. */
    email: text('email').notNull(),
    displayName: text('display_name').notNull().default(''),

    /**
     * scrypt output, self-describing as `scrypt$N$r$p$salt$hash` so parameters
     * can be raised later without invalidating existing credentials.
     */
    passwordHash: text('password_hash').notNull(),

    role: text('role').$type<UserRole>().notNull().default('viewer'),
    locale: text('locale').$type<Locale>().notNull().default('en'),

    /** Reset on success; drives temporary lockout while it exceeds the limit. */
    failedLoginCount: integer('failed_login_count').notNull().default(0),
    lockedUntil: integer('locked_until', { mode: 'timestamp_ms' }),
    lastLoginAt: integer('last_login_at', { mode: 'timestamp_ms' }),

    /** Soft-disable: retains audit history that a hard delete would orphan. */
    isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),

    ...stamps,
  },
  (table) => [uniqueIndex('users_email_unique').on(table.email)],
);

export const sessions = sqliteTable(
  'sessions',
  {
    id: text('id').primaryKey(),

    userId: integer('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),

    /**
     * SHA-256 of the opaque bearer token. The token itself exists only in the
     * client cookie, so a database read cannot be replayed as a session.
     */
    tokenHash: text('token_hash').notNull(),

    /** Bound at creation; a mismatch on use is treated as session theft. */
    userAgentHash: text('user_agent_hash').notNull().default(''),
    ipHash: text('ip_hash').notNull().default(''),

    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
    lastSeenAt: integer('last_seen_at', { mode: 'timestamp_ms' }).notNull().default(now),

    /** Hard ceiling, independent of activity. Never extended by use. */
    absoluteExpiresAt: integer('absolute_expires_at', { mode: 'timestamp_ms' }).notNull(),

    revokedAt: integer('revoked_at', { mode: 'timestamp_ms' }),
  },
  (table) => [
    uniqueIndex('sessions_token_hash_unique').on(table.tokenHash),
    index('sessions_user_idx').on(table.userId),
    index('sessions_expiry_idx').on(table.absoluteExpiresAt),
  ],
);

/**
 * Append-only record of every authentication event and business mutation.
 * Nothing in the application updates or deletes from this table.
 */
export const auditLog = sqliteTable(
  'audit_log',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),

    /** Null for pre-authentication events such as a failed sign-in. */
    actorUserId: integer('actor_user_id').references(() => users.id, { onDelete: 'set null' }),
    actorEmail: text('actor_email').notNull().default(''),

    action: text('action').notNull(),
    entityType: text('entity_type').notNull().default(''),
    entityId: text('entity_id').notNull().default(''),

    /** JSON object of non-sensitive context. Never holds secrets or passwords. */
    metadata: text('metadata').notNull().default('{}'),

    ipHash: text('ip_hash').notNull().default(''),
    outcome: text('outcome').$type<'success' | 'failure'>().notNull().default('success'),

    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull().default(now),
  },
  (table) => [
    index('audit_actor_idx').on(table.actorUserId),
    index('audit_created_idx').on(table.createdAt),
    index('audit_entity_idx').on(table.entityType, table.entityId),
  ],
);

/**
 * Fixed-window rate-limit counters.
 *
 * Persisted rather than held in module memory so limits survive a process
 * restart and hold across the multiple workers a Next.js deployment runs --
 * an in-memory counter would let an attacker reset the window by forcing a
 * restart, or simply spread attempts across workers.
 */
export const rateLimits = sqliteTable(
  'rate_limits',
  {
    /** `<bucket>:<hashed subject>` -- never a raw IP or email. */
    key: text('key').primaryKey(),
    count: integer('count').notNull().default(0),
    windowStartedAt: integer('window_started_at', { mode: 'timestamp_ms' }).notNull(),
    expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
  },
  (table) => [index('rate_limits_expiry_idx').on(table.expiresAt)],
);

// ---------------------------------------------------------------------------
// Service catalog -- the product intelligence library (产品情报库)
// ---------------------------------------------------------------------------

export const products = sqliteTable(
  'products',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),

    category: text('category').notNull().default(''),
    product: text('product').notNull(),

    description: text('description').notNull().default(''),
    competitors: text('competitors').notNull().default(''),
    useCases: text('use_cases').notNull().default(''),
    industries: text('industries').notNull().default(''),
    companySize: text('company_size').notNull().default(''),
    customerGate: text('customer_gate').notNull().default(''),
    painPoints: text('pain_points').notNull().default(''),
    strengths: text('strengths').notNull().default(''),
    weaknesses: text('weaknesses').notNull().default(''),
    productEntry: text('product_entry').notNull().default(''),
    bdMotion: text('bd_motion').notNull().default(''),
    notes: text('notes').notNull().default(''),
    source: text('source').notNull().default(''),

    priority: text('priority').$type<Priority>().notNull().default('P3'),
    knowledge: text('knowledge').$type<KnowledgeLevel>().notNull().default('To Learn'),
    confidence: text('confidence').$type<ConfidenceLevel>().notNull().default('Hypothesis'),
    status: text('status').$type<ProductStatus>().notNull().default('Not Reviewed'),
    owner: text('owner').notNull().default(''),

    // Solution-selling layer: sell the architecture, not the SKU.
    commercialCategory: text('commercial_category')
      .$type<CommercialCategory>()
      .notNull()
      .default('Standalone / Other'),
    sellMode: text('sell_mode').$type<SellMode>().notNull().default('Standalone'),
    solutionStory: text('solution_story').notNull().default(''),
    primaryCompetitor: text('primary_competitor').notNull().default(''),
    referenceCustomers: text('reference_customers').notNull().default(''),
    tencentEdge: text('tencent_edge').notNull().default(''),

    // Three-layer messaging library.
    messagingTechnical: text('messaging_technical').notNull().default(''),
    messagingBusiness: text('messaging_business').notNull().default(''),
    messagingExecutive: text('messaging_executive').notNull().default(''),
    messagingSafeClaim: text('messaging_safe_claim').notNull().default(''),

    // Qualification and selling system.
    discovery: text('discovery').notNull().default(''),
    buyingSignals: text('buying_signals').notNull().default(''),
    redFlags: text('red_flags').notNull().default(''),
    proofRequired: text('proof_required').notNull().default(''),
    objections: text('objections').notNull().default(''),
    replacements: text('replacements').notNull().default(''),
    learningChecklist: text('learning_checklist').notNull().default(''),

    // Priority scorecard: six axes, 1-5 each.
    scoreDemand: integer('score_demand').notNull().default(3),
    scoreRightToWin: integer('score_right_to_win').notNull().default(3),
    scoreEntry: integer('score_entry').notNull().default(3),
    scorePoc: integer('score_poc').notNull().default(3),
    scoreExpansion: integer('score_expansion').notNull().default(3),
    scoreRevenue: integer('score_revenue').notNull().default(3),
    scoreRationale: text('score_rationale').notNull().default(''),
    scoreValidation: text('score_validation').notNull().default(''),

    /**
     * Upstream linkage. `upstreamCode` is the Tencent Cloud product short code
     * (e.g. `cvm`); it is the join key for catalog syncs and is unique when
     * present, so a repeated sync updates rather than duplicates.
     */
    upstreamCode: text('upstream_code'),
    upstreamSyncedAt: integer('upstream_synced_at', { mode: 'timestamp_ms' }),

    ...stamps,
  },
  (table) => [
    uniqueIndex('products_upstream_code_unique').on(table.upstreamCode),
    index('products_priority_idx').on(table.priority),
    index('products_category_idx').on(table.category),
    index('products_commercial_idx').on(table.commercialCategory),
    index('products_status_idx').on(table.status),
  ],
);

/**
 * Evidence backing a claim about a product.
 *
 * Normalised out of the product row (the source application kept a JSON blob)
 * so `canSay` and `level` can be filtered and aggregated in SQL -- the whole
 * point of the Evidence Studio is answering "which claims may I actually make",
 * which is a query, not a document scan.
 */
export const productEvidence = sqliteTable(
  'product_evidence',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),

    productId: integer('product_id')
      .notNull()
      .references(() => products.id, { onDelete: 'cascade' }),

    level: text('level').$type<EvidenceLevel>().notNull().default('Assumption'),
    statement: text('statement').notNull().default(''),
    canSay: text('can_say').$type<CanSay>().notNull().default('No'),
    source: text('source').notNull().default(''),
    confidence: text('confidence').$type<EvidenceConfidence>().notNull().default('Low'),

    /** ISO date (YYYY-MM-DD) the claim was last checked against its source. */
    verifiedOn: text('verified_on').notNull().default(''),
    notes: text('notes').notNull().default(''),

    /** Stable ordering within a product; the UI reorders by rewriting these. */
    position: integer('position').notNull().default(0),

    ...stamps,
  },
  (table) => [
    index('evidence_product_idx').on(table.productId, table.position),
    index('evidence_can_say_idx').on(table.canSay),
  ],
);

// ---------------------------------------------------------------------------
// Account pipeline
// ---------------------------------------------------------------------------

export const accounts = sqliteTable(
  'accounts',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),

    company: text('company').notNull(),
    region: text('region').notNull().default(''),
    industry: text('industry').notNull().default(''),
    size: text('size').$type<AccountSize>().notNull().default('Scale-up'),

    incumbent: text('incumbent').notNull().default(''),
    products: text('products').notNull().default(''),
    pain: text('pain').notNull().default(''),
    trigger: text('trigger').notNull().default(''),
    contact: text('contact').notNull().default(''),
    path: text('path').notNull().default(''),

    stage: text('stage').$type<AccountStage>().notNull().default('Target'),
    fit: text('fit').$type<AccountFit>().notNull().default('Medium'),

    nextAction: text('next_action').notNull().default(''),
    /** ISO date (YYYY-MM-DD); stored as text so it sorts lexicographically. */
    dueOn: text('due_on').notNull().default(''),
    notes: text('notes').notNull().default(''),

    ...stamps,
  },
  (table) => [
    index('accounts_stage_idx').on(table.stage),
    index('accounts_company_idx').on(table.company),
  ],
);

/**
 * The account research workspace: one row per account, holding the long-form
 * thesis fields. Split from `accounts` because the pipeline table is read on
 * every list render while these fields are only read on the detail page.
 */
export const accountResearch = sqliteTable('account_research', {
  accountId: integer('account_id')
    .primaryKey()
    .references(() => accounts.id, { onDelete: 'cascade' }),

  // Research
  companySnapshot: text('company_snapshot').notNull().default(''),
  recentNews: text('recent_news').notNull().default(''),
  funding: text('funding').notNull().default(''),
  stack: text('stack').notNull().default(''),
  hiring: text('hiring').notNull().default(''),
  vendors: text('vendors').notNull().default(''),
  triggers: text('triggers').notNull().default(''),
  pains: text('pains').notNull().default(''),
  gaps: text('gaps').notNull().default(''),

  // Account thesis
  whyAccount: text('why_account').notNull().default(''),
  whyNow: text('why_now').notNull().default(''),
  primaryPain: text('primary_pain').notNull().default(''),
  wedge: text('wedge').notNull().default(''),
  buyer: text('buyer').notNull().default(''),
  proof: text('proof').notNull().default(''),
  expansion: text('expansion').notNull().default(''),
  validationStep: text('validation_step').notNull().default(''),
  finalThesis: text('final_thesis').notNull().default(''),

  // Buying committee
  economicBuyer: text('economic_buyer').notNull().default(''),
  technicalBuyer: text('technical_buyer').notNull().default(''),
  champion: text('champion').notNull().default(''),
  usersInfluence: text('users_influence').notNull().default(''),
  blockers: text('blockers').notNull().default(''),
  procurement: text('procurement').notNull().default(''),
  warmPath: text('warm_path').notNull().default(''),

  // Evidence and sources
  sources: text('sources').notNull().default(''),
  confidence: text('confidence').notNull().default(''),
  lastVerified: text('last_verified').notNull().default(''),

  ...stamps,
});

// ---------------------------------------------------------------------------
// Execution surfaces
// ---------------------------------------------------------------------------

export const todos = sqliteTable(
  'todos',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),

    title: text('title').notNull(),
    detail: text('detail').notNull().default(''),
    owner: text('owner').$type<TodoOwner>().notNull().default('Me'),
    priority: text('priority').$type<TodoPriority>().notNull().default('P2'),
    status: text('status').$type<TodoStatus>().notNull().default('Backlog'),
    dueOn: text('due_on').notNull().default(''),

    /** Validated as http(s) at the write boundary to keep `javascript:` out. */
    link: text('link').notNull().default(''),

    /** Ordering within a Kanban column. */
    position: integer('position').notNull().default(0),

    ...stamps,
  },
  (table) => [index('todos_status_idx').on(table.status, table.position)],
);

export const sopSteps = sqliteTable(
  'sop_steps',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    body: text('body').notNull().default(''),
    position: integer('position').notNull().default(0),
    ...stamps,
  },
  (table) => [index('sop_position_idx').on(table.position)],
);

export const motions = sqliteTable('motions', {
  id: integer('id').primaryKey({ autoIncrement: true }),

  opportunity: text('opportunity').notNull(),
  triggerSignals: text('trigger_signals').notNull().default(''),
  icp: text('icp').notNull().default(''),
  discoveryQuestions: text('discovery_questions').notNull().default(''),
  wedgeProduct: text('wedge_product').notNull().default(''),
  pocStrategy: text('poc_strategy').notNull().default(''),
  successMetrics: text('success_metrics').notNull().default(''),
  expansionPath: text('expansion_path').notNull().default(''),
  risks: text('risks').notNull().default(''),
  evidenceRequired: text('evidence_required').notNull().default(''),

  ...stamps,
});

/**
 * Weekly CEO review answers. The question set is a fixed, code-owned list, so
 * only the answer is persisted, keyed by question index.
 */
export const reviewAnswers = sqliteTable(
  'review_answers',
  {
    questionIndex: integer('question_index').notNull(),

    /** Answers are per-user: the review is a personal operating cadence. */
    userId: integer('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),

    answer: text('answer').notNull().default(''),
    ...stamps,
  },
  (table) => [
    primaryKey({ columns: [table.userId, table.questionIndex] }),
    index('review_user_idx').on(table.userId),
  ],
);

// ---------------------------------------------------------------------------
// Localisation
// ---------------------------------------------------------------------------

/**
 * Translation memory for user-authored content.
 *
 * Source text is never overwritten. A translation is an additional row keyed by
 * (entity, field, locale), carrying its provenance and review status, so the UI
 * can always show which language a value was actually written in and whether a
 * human approved the rendering. That separation is what makes auto-translation
 * safe to switch on for a system whose whole discipline is "do not state a
 * claim you cannot support".
 */
export const translations = sqliteTable(
  'translations',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),

    entityType: text('entity_type').notNull(),
    entityId: integer('entity_id').notNull(),
    field: text('field').notNull(),
    locale: text('locale').$type<Locale>().notNull(),

    value: text('value').notNull(),

    /** Locale the translation was produced from, for staleness detection. */
    sourceLocale: text('source_locale').$type<Locale>().notNull(),

    /**
     * SHA-256 of the source text at translation time. When the source changes
     * this no longer matches and the translation is reported as stale rather
     * than silently served.
     */
    sourceHash: text('source_hash').notNull(),

    origin: text('origin').$type<TranslationSource>().notNull().default('machine'),
    status: text('status').$type<TranslationStatus>().notNull().default('needs-review'),

    reviewedBy: integer('reviewed_by').references(() => users.id, { onDelete: 'set null' }),
    reviewedAt: integer('reviewed_at', { mode: 'timestamp_ms' }),

    ...stamps,
  },
  (table) => [
    uniqueIndex('translations_target_unique').on(
      table.entityType,
      table.entityId,
      table.field,
      table.locale,
    ),
    index('translations_status_idx').on(table.status),
  ],
);

// ---------------------------------------------------------------------------
// Upstream synchronisation
// ---------------------------------------------------------------------------

/** One row per catalog sync attempt, successful or not. */
export const catalogSyncRuns = sqliteTable(
  'catalog_sync_runs',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),

    startedAt: integer('started_at', { mode: 'timestamp_ms' }).notNull().default(now),
    finishedAt: integer('finished_at', { mode: 'timestamp_ms' }),

    status: text('status')
      .$type<'running' | 'success' | 'failed'>()
      .notNull()
      .default('running'),

    /** Which upstream produced this run: `tencent-api` or `local-corpus`. */
    sourceKind: text('source_kind').notNull().default('local-corpus'),

    productsSeen: integer('products_seen').notNull().default(0),
    productsCreated: integer('products_created').notNull().default(0),
    productsUpdated: integer('products_updated').notNull().default(0),

    /** Upstream error text, truncated; never contains request credentials. */
    error: text('error').notNull().default(''),

    triggeredBy: integer('triggered_by').references(() => users.id, { onDelete: 'set null' }),
  },
  (table) => [index('sync_started_idx').on(table.startedAt)],
);

// ---------------------------------------------------------------------------
// Relations
// ---------------------------------------------------------------------------

export const usersRelations = relations(users, ({ many }) => ({
  sessions: many(sessions),
  reviewAnswers: many(reviewAnswers),
}));

export const sessionsRelations = relations(sessions, ({ one }) => ({
  user: one(users, { fields: [sessions.userId], references: [users.id] }),
}));

export const productsRelations = relations(products, ({ many }) => ({
  evidence: many(productEvidence),
}));

export const productEvidenceRelations = relations(productEvidence, ({ one }) => ({
  product: one(products, { fields: [productEvidence.productId], references: [products.id] }),
}));

export const accountsRelations = relations(accounts, ({ one }) => ({
  research: one(accountResearch, {
    fields: [accounts.id],
    references: [accountResearch.accountId],
  }),
}));

export const accountResearchRelations = relations(accountResearch, ({ one }) => ({
  account: one(accounts, { fields: [accountResearch.accountId], references: [accounts.id] }),
}));

export const reviewAnswersRelations = relations(reviewAnswers, ({ one }) => ({
  user: one(users, { fields: [reviewAnswers.userId], references: [users.id] }),
}));

// ---------------------------------------------------------------------------
// Inferred row types -- the "typesafe schema" the PRD asks for, derived rather
// than hand-written so they cannot drift from the columns above.
// ---------------------------------------------------------------------------

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;

export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;

export type AuditEntry = typeof auditLog.$inferSelect;
export type NewAuditEntry = typeof auditLog.$inferInsert;

export type Product = typeof products.$inferSelect;
export type NewProduct = typeof products.$inferInsert;

export type ProductEvidence = typeof productEvidence.$inferSelect;
export type NewProductEvidence = typeof productEvidence.$inferInsert;

export type Account = typeof accounts.$inferSelect;
export type NewAccount = typeof accounts.$inferInsert;

export type AccountResearch = typeof accountResearch.$inferSelect;
export type NewAccountResearch = typeof accountResearch.$inferInsert;

export type Todo = typeof todos.$inferSelect;
export type NewTodo = typeof todos.$inferInsert;

export type SopStep = typeof sopSteps.$inferSelect;
export type NewSopStep = typeof sopSteps.$inferInsert;

export type Motion = typeof motions.$inferSelect;
export type NewMotion = typeof motions.$inferInsert;

export type ReviewAnswer = typeof reviewAnswers.$inferSelect;
export type NewReviewAnswer = typeof reviewAnswers.$inferInsert;

export type Translation = typeof translations.$inferSelect;
export type NewTranslation = typeof translations.$inferInsert;

export type CatalogSyncRun = typeof catalogSyncRuns.$inferSelect;
export type NewCatalogSyncRun = typeof catalogSyncRuns.$inferInsert;
