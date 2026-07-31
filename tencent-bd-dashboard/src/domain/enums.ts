/**
 * Closed vocabularies for the BD operating system.
 *
 * Declared once, as `readonly` tuples, and consumed three ways:
 *   - Drizzle column types (`.$type<Priority>()`) for compile-time DB safety
 *   - Zod `z.enum(...)` for runtime validation at every trust boundary
 *   - UI filter/select options, so a widget can never offer an invalid value
 *
 * Adding a member here propagates to all three without further edits, which is
 * what keeps the persisted data and the accepted input provably in step.
 *
 * This module is intentionally free of server-only imports: the client bundles
 * it to render selects. It must never grow a secret or an I/O dependency.
 */

export const PRIORITIES = ['P1', 'P2', 'P3'] as const;
export type Priority = (typeof PRIORITIES)[number];

export const TODO_PRIORITIES = ['P0', 'P1', 'P2', 'P3'] as const;
export type TodoPriority = (typeof TODO_PRIORITIES)[number];

export const KNOWLEDGE_LEVELS = [
  'To Learn',
  'Learning',
  'Working Knowledge',
  'Can Sell',
] as const;
export type KnowledgeLevel = (typeof KNOWLEDGE_LEVELS)[number];

export const CONFIDENCE_LEVELS = [
  'Hypothesis',
  'Internal Input',
  'Customer Validated',
  'Verified',
] as const;
export type ConfidenceLevel = (typeof CONFIDENCE_LEVELS)[number];

export const PRODUCT_STATUSES = [
  'Not Reviewed',
  'Reviewed',
  'Needs Validation',
  'Approved',
] as const;
export type ProductStatus = (typeof PRODUCT_STATUSES)[number];

export const COMMERCIAL_CATEGORIES = [
  'Infrastructure Architecture',
  'Communication',
  'Media Services',
  'Content Delivery & Edge',
  'Security',
  'AI & Model Services',
  'Standalone / Other',
] as const;
export type CommercialCategory = (typeof COMMERCIAL_CATEGORIES)[number];

export const SELL_MODES = ['Bundle', 'Standalone'] as const;
export type SellMode = (typeof SELL_MODES)[number];

export const ACCOUNT_STAGES = [
  'Target',
  'Researching',
  'Contacted',
  'Discovery',
  'Qualified',
  'POC',
  'Commercial',
  'Won',
  'Nurture',
] as const;
export type AccountStage = (typeof ACCOUNT_STAGES)[number];

export const ACCOUNT_SIZES = ['Startup', 'Scale-up', 'Mid-Market', 'Enterprise'] as const;
export type AccountSize = (typeof ACCOUNT_SIZES)[number];

export const ACCOUNT_FITS = ['High', 'Medium', 'Low'] as const;
export type AccountFit = (typeof ACCOUNT_FITS)[number];

export const TODO_STATUSES = ['Backlog', 'This Week', 'In Progress', 'Done'] as const;
export type TodoStatus = (typeof TODO_STATUSES)[number];

export const TODO_OWNERS = ['Me', 'Mentor', 'SA', 'Marketing', 'Partner'] as const;
export type TodoOwner = (typeof TODO_OWNERS)[number];

/**
 * Evidence levels, ordered weakest-to-strongest claim support. The Evidence
 * Studio exists to stop unsupported outcome claims reaching a customer, so the
 * ordering is load-bearing, not cosmetic.
 */
export const EVIDENCE_LEVELS = [
  'Assumption',
  'Inference',
  'Internal Fact',
  'Official Fact',
  'Benchmark',
  'Customer Validation',
  'Customer Outcome',
] as const;
export type EvidenceLevel = (typeof EVIDENCE_LEVELS)[number];

export const CAN_SAY_OPTIONS = ['Yes', 'Qualified', 'Internal Only', 'No'] as const;
export type CanSay = (typeof CAN_SAY_OPTIONS)[number];

export const EVIDENCE_CONFIDENCE = ['Low', 'Medium', 'High', 'Verified'] as const;
export type EvidenceConfidence = (typeof EVIDENCE_CONFIDENCE)[number];

export const USER_ROLES = ['admin', 'editor', 'viewer'] as const;
export type UserRole = (typeof USER_ROLES)[number];

/**
 * Supported UI locales. `zh-Hans` and `zh-Hant` are distinct BCP-47 script
 * subtags, not region tags: the difference the PRD cares about is the writing
 * system, which is exactly what `Hans`/`Hant` encode.
 */
export const LOCALES = ['en', 'zh-Hans', 'zh-Hant'] as const;
export type Locale = (typeof LOCALES)[number];
export const DEFAULT_LOCALE: Locale = 'en';

/**
 * Provenance of a stored translation. Surfaced in the UI so a BD rep never
 * quotes machine output to a customer believing a human approved it.
 */
export const TRANSLATION_SOURCES = ['human', 'machine', 'script-conversion'] as const;
export type TranslationSource = (typeof TRANSLATION_SOURCES)[number];

export const TRANSLATION_STATUSES = ['draft', 'needs-review', 'approved'] as const;
export type TranslationStatus = (typeof TRANSLATION_STATUSES)[number];

/** The six axes of the product priority scorecard, each scored 1-5. */
export const PRIORITY_DIMENSIONS = [
  'demand',
  'rightToWin',
  'entry',
  'poc',
  'expansion',
  'revenue',
] as const;
export type PriorityDimension = (typeof PRIORITY_DIMENSIONS)[number];

export const PRIORITY_SCORE_MIN = 1;
export const PRIORITY_SCORE_MAX = 5;
export const PRIORITY_SCORE_TOTAL_MAX = PRIORITY_DIMENSIONS.length * PRIORITY_SCORE_MAX;

/**
 * Product taxonomy carried over from the source catalog. Used for the category
 * filter; free-text categories from an upstream sync are still accepted, so
 * this is a suggestion list rather than a constraint.
 */
export const PRODUCT_CATEGORIES = [
  'Compute',
  'Container & Middleware',
  'Storage',
  'Database',
  'Networking',
  'CDN & Edge',
  'Video & Real-Time',
  'Security',
  'Analytics',
  'Private Cloud & Software',
  'AI & Machine Learning',
  'Development & Operations',
  'Communication & Enterprise',
  'Office Collaboration',
  'IoT & Industry',
] as const;
export type ProductCategory = (typeof PRODUCT_CATEGORIES)[number];
