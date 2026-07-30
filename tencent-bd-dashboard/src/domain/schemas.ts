import { z } from 'zod';

import {
  ACCOUNT_FITS,
  ACCOUNT_SIZES,
  ACCOUNT_STAGES,
  CAN_SAY_OPTIONS,
  COMMERCIAL_CATEGORIES,
  CONFIDENCE_LEVELS,
  EVIDENCE_CONFIDENCE,
  EVIDENCE_LEVELS,
  KNOWLEDGE_LEVELS,
  LOCALES,
  PRIORITIES,
  PRIORITY_SCORE_MAX,
  PRIORITY_SCORE_MIN,
  PRODUCT_STATUSES,
  SELL_MODES,
  TODO_OWNERS,
  TODO_PRIORITIES,
  TODO_STATUSES,
  USER_ROLES,
} from './enums';

/**
 * Runtime validation for every value that crosses a trust boundary.
 *
 * The Drizzle schema gives compile-time types; these give the runtime guarantee
 * that what lands in those columns actually matches. Server Actions receive
 * `FormData`, which is `unknown` as far as the type system is concerned, so
 * without this layer the compile-time types would be a comfortable fiction.
 *
 * Three rules run throughout:
 *
 *   1. Every string is length-bounded. An unbounded text field is a cheap
 *      denial-of-service and an unbounded row in SQLite.
 *   2. Every enum is the closed tuple from `./enums`, so a crafted POST cannot
 *      write a status the UI will never render.
 *   3. Strings are trimmed before validation, so " " does not satisfy a
 *      required field.
 */

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/** Bounded free text. Empty is allowed; the column default is also empty. */
const text = (max: number) => z.string().trim().max(max);

/** Bounded required text. */
const requiredText = (max: number, label: string) =>
  z.string().trim().min(1, `${label} is required`).max(max);

/** Long-form field. 20k characters is far above any real entry. */
const longText = () => text(20_000);

/** ISO calendar date, or empty. Rejects `2024-13-45`, which a regex would not. */
const isoDate = z
  .string()
  .trim()
  .max(10)
  .refine(
    (value) => value === '' || (/^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(value))),
    { message: 'Must be a valid date in YYYY-MM-DD form' },
  );

/**
 * An http(s) URL, or empty.
 *
 * The scheme allowlist is the point: without it, `javascript:alert(1)` is a
 * perfectly valid URL, and rendering it into an anchor's href would be stored
 * XSS that React's escaping does not prevent.
 */
const httpUrl = z
  .string()
  .trim()
  .max(2048)
  .refine(
    (value) => {
      if (value === '') return true;
      try {
        const parsed = new URL(value);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
      } catch {
        return false;
      }
    },
    { message: 'Must be an http or https URL' },
  );

/** Positive integer id, accepting the string form `FormData` always yields. */
export const idSchema = z.coerce.number().int().positive();

const scoreValue = z.coerce.number().int().min(PRIORITY_SCORE_MIN).max(PRIORITY_SCORE_MAX);

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/**
 * Email is lowercased so the unique index cannot be defeated by case, and
 * capped well below the RFC maximum -- addresses that long are not real, and
 * the cap keeps a huge value from reaching the hasher.
 */
export const emailSchema = z.string().trim().toLowerCase().email().max(254);

export const loginSchema = z.object({
  email: emailSchema,
  // Deliberately not length-policed beyond an upper bound: rejecting a short
  // password here would tell an attacker the policy applies to a real account.
  password: z.string().min(1).max(200),
  next: z.string().max(512).optional(),
});
export type LoginInput = z.infer<typeof loginSchema>;

export const localeSchema = z.enum(LOCALES);

// ---------------------------------------------------------------------------
// Service catalog
// ---------------------------------------------------------------------------

export const productSchema = z.object({
  category: text(120),
  product: requiredText(200, 'Product name'),

  description: longText(),
  competitors: longText(),
  useCases: longText(),
  industries: longText(),
  companySize: text(200),
  customerGate: longText(),
  painPoints: longText(),
  strengths: longText(),
  weaknesses: longText(),
  productEntry: longText(),
  bdMotion: longText(),
  notes: longText(),

  priority: z.enum(PRIORITIES),
  knowledge: z.enum(KNOWLEDGE_LEVELS),
  confidence: z.enum(CONFIDENCE_LEVELS),
  status: z.enum(PRODUCT_STATUSES),
});
export type ProductInput = z.infer<typeof productSchema>;

export const productStorySchema = z.object({
  commercialCategory: z.enum(COMMERCIAL_CATEGORIES),
  sellMode: z.enum(SELL_MODES),
  primaryCompetitor: text(500),
  useCases: longText(),
  referenceCustomers: longText(),
  tencentEdge: longText(),
  solutionStory: longText(),
});
export type ProductStoryInput = z.infer<typeof productStorySchema>;

export const priorityScoreSchema = z.object({
  demand: scoreValue,
  rightToWin: scoreValue,
  entry: scoreValue,
  poc: scoreValue,
  expansion: scoreValue,
  revenue: scoreValue,
  rationale: longText(),
  validation: longText(),
});
export type PriorityScoreInput = z.infer<typeof priorityScoreSchema>;

export const evidenceRowSchema = z.object({
  level: z.enum(EVIDENCE_LEVELS),
  statement: text(4000),
  canSay: z.enum(CAN_SAY_OPTIONS),
  source: text(1000),
  confidence: z.enum(EVIDENCE_CONFIDENCE),
  verifiedOn: isoDate,
  notes: text(2000),
});
export type EvidenceRowInput = z.infer<typeof evidenceRowSchema>;

export const evidenceStudioSchema = z.object({
  // Bounded so one product cannot accumulate an unbounded evidence table.
  rows: z.array(evidenceRowSchema).max(200),

  messagingTechnical: longText(),
  messagingBusiness: longText(),
  messagingExecutive: longText(),
  messagingSafeClaim: longText(),

  discovery: longText(),
  buyingSignals: longText(),
  redFlags: longText(),
  proofRequired: longText(),
  objections: longText(),
  replacements: longText(),
  learningChecklist: longText(),
});
export type EvidenceStudioInput = z.infer<typeof evidenceStudioSchema>;

// ---------------------------------------------------------------------------
// Account pipeline
// ---------------------------------------------------------------------------

export const accountSchema = z.object({
  company: requiredText(200, 'Company'),
  region: text(200),
  industry: text(200),
  size: z.enum(ACCOUNT_SIZES),

  incumbent: longText(),
  products: longText(),
  pain: longText(),
  trigger: longText(),
  contact: text(500),
  path: longText(),

  stage: z.enum(ACCOUNT_STAGES),
  fit: z.enum(ACCOUNT_FITS),

  nextAction: longText(),
  dueOn: isoDate,
  notes: longText(),
});
export type AccountInput = z.infer<typeof accountSchema>;

export const accountResearchSchema = z.object({
  companySnapshot: longText(),
  recentNews: longText(),
  funding: longText(),
  stack: longText(),
  hiring: longText(),
  vendors: longText(),
  triggers: longText(),
  pains: longText(),
  gaps: longText(),

  whyAccount: longText(),
  whyNow: longText(),
  primaryPain: longText(),
  wedge: longText(),
  buyer: longText(),
  proof: longText(),
  expansion: longText(),
  validationStep: longText(),
  finalThesis: longText(),

  economicBuyer: longText(),
  technicalBuyer: longText(),
  champion: longText(),
  usersInfluence: longText(),
  blockers: longText(),
  procurement: longText(),
  warmPath: longText(),

  sources: longText(),
  confidence: text(500),
  lastVerified: isoDate,
});
export type AccountResearchInput = z.infer<typeof accountResearchSchema>;

// ---------------------------------------------------------------------------
// Execution surfaces
// ---------------------------------------------------------------------------

export const todoSchema = z.object({
  title: requiredText(300, 'Task'),
  detail: longText(),
  owner: z.enum(TODO_OWNERS),
  priority: z.enum(TODO_PRIORITIES),
  status: z.enum(TODO_STATUSES),
  dueOn: isoDate,
  link: httpUrl,
});
export type TodoInput = z.infer<typeof todoSchema>;

export const todoMoveSchema = z.object({
  id: idSchema,
  status: z.enum(TODO_STATUSES),
  position: z.coerce.number().int().min(0).max(10_000),
});
export type TodoMoveInput = z.infer<typeof todoMoveSchema>;

export const sopChecklistSchema = z.object({
  steps: z.array(text(2000)).max(200),
});
export type SopChecklistInput = z.infer<typeof sopChecklistSchema>;

export const motionSchema = z.object({
  opportunity: requiredText(300, 'Opportunity'),
  triggerSignals: longText(),
  icp: longText(),
  discoveryQuestions: longText(),
  wedgeProduct: longText(),
  pocStrategy: longText(),
  successMetrics: longText(),
  expansionPath: longText(),
  risks: longText(),
  evidenceRequired: longText(),
});
export type MotionInput = z.infer<typeof motionSchema>;

export const reviewAnswerSchema = z.object({
  // Upper bound matches the code-owned question list length; see
  // `@/domain/review-questions`.
  questionIndex: z.coerce.number().int().min(0).max(200),
  answer: text(10_000),
});
export type ReviewAnswerInput = z.infer<typeof reviewAnswerSchema>;

// ---------------------------------------------------------------------------
// Translation
// ---------------------------------------------------------------------------

/** Entity types whose fields may be machine-translated. */
export const TRANSLATABLE_ENTITIES = ['product', 'account', 'motion', 'todo'] as const;
export type TranslatableEntity = (typeof TRANSLATABLE_ENTITIES)[number];

/**
 * Upper bound on a single translation request.
 *
 * The upstream machine-translation API bills per character and enforces its own
 * limit; failing here is cheaper and gives a better message than failing there.
 */
export const TRANSLATION_MAX_CHARS = 5000;

export const translationRequestSchema = z.object({
  entityType: z.enum(TRANSLATABLE_ENTITIES),
  entityId: idSchema,
  field: z
    .string()
    .trim()
    // Field names are used to index a fixed allowlist; constraining the shape
    // here keeps anything exotic from reaching that lookup.
    .regex(/^[a-zA-Z][a-zA-Z0-9]{0,40}$/, 'Unknown field'),
  sourceLocale: localeSchema,
  targetLocale: localeSchema,
});
export type TranslationRequestInput = z.infer<typeof translationRequestSchema>;

export const translationReviewSchema = z.object({
  id: idSchema,
  // 'draft' is a machine-set initial state, never a reviewer's own choice: an
  // admin reviewing a translation may only approve it or send it back for
  // rework, so those are the only two values this action accepts.
  status: z.enum(['approved', 'needs-review']),
  value: text(TRANSLATION_MAX_CHARS * 2),
});
export type TranslationReviewInput = z.infer<typeof translationReviewSchema>;

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------

export const userCreateSchema = z.object({
  email: emailSchema,
  displayName: text(200),
  role: z.enum(USER_ROLES),
});
export type UserCreateInput = z.infer<typeof userCreateSchema>;

export const userUpdateSchema = z.object({
  id: idSchema,
  displayName: text(200),
  role: z.enum(USER_ROLES),
  isActive: z.coerce.boolean(),
});
export type UserUpdateInput = z.infer<typeof userUpdateSchema>;

// ---------------------------------------------------------------------------
// Catalog filters (query string -> typed filter)
// ---------------------------------------------------------------------------

/**
 * Filter state, parsed from the URL.
 *
 * `.catch()` on every field means a hand-edited or stale query string degrades
 * to "no filter" instead of erroring the page. A filter is a view preference,
 * not an assertion -- rejecting the whole request over one bad value would be
 * the wrong trade.
 */
export const productFilterSchema = z.object({
  q: z.string().trim().max(200).catch(''),
  category: z.string().trim().max(120).catch(''),
  commercial: z.enum(COMMERCIAL_CATEGORIES).or(z.literal('')).catch(''),
  sellMode: z.enum(SELL_MODES).or(z.literal('')).catch(''),
  priority: z.enum(PRIORITIES).or(z.literal('')).catch(''),
  knowledge: z.enum(KNOWLEDGE_LEVELS).or(z.literal('')).catch(''),
  status: z.enum(PRODUCT_STATUSES).or(z.literal('')).catch(''),
  page: z.coerce.number().int().min(1).max(10_000).catch(1),
});
export type ProductFilter = z.infer<typeof productFilterSchema>;

export const accountFilterSchema = z.object({
  q: z.string().trim().max(200).catch(''),
  stage: z.enum(ACCOUNT_STAGES).or(z.literal('')).catch(''),
  page: z.coerce.number().int().min(1).max(10_000).catch(1),
});
export type AccountFilter = z.infer<typeof accountFilterSchema>;

export const todoFilterSchema = z.object({
  owner: z.enum(TODO_OWNERS).or(z.literal('')).catch(''),
  priority: z.enum(TODO_PRIORITIES).or(z.literal('')).catch(''),
});
export type TodoFilter = z.infer<typeof todoFilterSchema>;

// ---------------------------------------------------------------------------
// FormData helpers
// ---------------------------------------------------------------------------

/**
 * Convert `FormData` to a plain object for Zod.
 *
 * Repeated keys collapse to an array, which is how checkbox groups and the
 * repeating evidence rows arrive. `File` entries are dropped: no schema here
 * accepts one, and letting a file through would only ever be a mistake.
 */
export function formDataToObject(formData: FormData): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const [key, value] of formData.entries()) {
    if (value instanceof File) continue;

    const existing = result[key];
    if (existing === undefined) {
      result[key] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      result[key] = [existing, value];
    }
  }

  return result;
}

/** Field-keyed validation errors, shaped for rendering next to each input. */
export type FieldErrors = Record<string, string[]>;

export function toFieldErrors(error: z.ZodError): FieldErrors {
  const errors: FieldErrors = {};
  for (const issue of error.issues) {
    const key = issue.path.join('.') || '_form';
    (errors[key] ??= []).push(issue.message);
  }
  return errors;
}
