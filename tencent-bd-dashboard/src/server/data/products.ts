import 'server-only';

import { and, asc, desc, eq, like, or, sql } from 'drizzle-orm';

import { db } from '@/db/client';
import { productEvidence, products } from '@/db/schema';
import type { NewProduct, Product, ProductEvidence } from '@/db/schema';
import { CONFIDENCE_LEVELS, KNOWLEDGE_LEVELS, PRIORITIES } from '@/domain/enums';
import type { ProductFilter } from '@/domain/schemas';

/**
 * Read and write access to the product intelligence library.
 *
 * Every query here is parameterised through Drizzle's query builder -- none of
 * it string-concatenates a filter value into SQL, which is what makes the
 * search box safe to wire directly to `like()` without a manual escape step.
 */

const PAGE_SIZE = 40;

export interface ProductListResult {
  readonly items: Product[];
  readonly total: number;
  readonly page: number;
  readonly pageSize: number;
}

/** Build the shared WHERE clause for both the page query and its count. */
function filterClause(filter: ProductFilter) {
  const clauses = [];

  if (filter.q) {
    const needle = `%${filter.q.toLowerCase()}%`;
    clauses.push(
      or(
        like(sql`lower(${products.product})`, needle),
        like(sql`lower(${products.category})`, needle),
        like(sql`lower(${products.competitors})`, needle),
        like(sql`lower(${products.useCases})`, needle),
        like(sql`lower(${products.industries})`, needle),
        like(sql`lower(${products.painPoints})`, needle),
      ),
    );
  }

  if (filter.category) clauses.push(eq(products.category, filter.category));
  if (filter.commercial) clauses.push(eq(products.commercialCategory, filter.commercial));
  if (filter.sellMode) clauses.push(eq(products.sellMode, filter.sellMode));
  if (filter.priority) clauses.push(eq(products.priority, filter.priority));
  if (filter.knowledge) clauses.push(eq(products.knowledge, filter.knowledge));
  if (filter.status) clauses.push(eq(products.status, filter.status));

  return clauses.length > 0 ? and(...clauses) : undefined;
}

export function listProducts(filter: ProductFilter): ProductListResult {
  const where = filterClause(filter);
  const offset = (filter.page - 1) * PAGE_SIZE;

  const items = db
    .select()
    .from(products)
    .where(where)
    .orderBy(
      // P1 first, then by descending computed score, mirroring the
      // recommendation the priority scorecard produces.
      sql`case ${products.priority} when 'P1' then 0 when 'P2' then 1 else 2 end`,
      desc(
        sql`${products.scoreDemand} + ${products.scoreRightToWin} + ${products.scoreEntry} + ${products.scorePoc} + ${products.scoreExpansion} + ${products.scoreRevenue}`,
      ),
      asc(products.product),
    )
    .limit(PAGE_SIZE)
    .offset(offset)
    .all();

  const countRow = db
    .select({ count: sql<number>`count(*)` })
    .from(products)
    .where(where)
    .get();

  return { items, total: countRow?.count ?? 0, page: filter.page, pageSize: PAGE_SIZE };
}

/**
 * All rows matching `filter`, unpaginated -- for CSV export, where the point
 * is to hand back everything the on-screen filter currently matches, not one
 * `PAGE_SIZE` page of it.
 */
export function listProductsForExport(filter: ProductFilter): Product[] {
  const where = filterClause(filter);
  return db.select().from(products).where(where).orderBy(asc(products.product)).all();
}

/** Distinct categories currently in use, for the filter dropdown. */
export function listCategories(): string[] {
  const rows = db
    .selectDistinct({ category: products.category })
    .from(products)
    .where(sql`${products.category} != ''`)
    .orderBy(asc(products.category))
    .all();
  return rows.map((r) => r.category);
}

export function getProduct(id: number): Product | undefined {
  return db.select().from(products).where(eq(products.id, id)).get();
}

export function getProductEvidence(productId: number): ProductEvidence[] {
  return db
    .select()
    .from(productEvidence)
    .where(eq(productEvidence.productId, productId))
    .orderBy(asc(productEvidence.position))
    .all();
}

export function createProduct(values: NewProduct): Product {
  return db.insert(products).values(values).returning().get();
}

export function updateProduct(id: number, values: Partial<NewProduct>): Product | undefined {
  return db
    .update(products)
    .set({ ...values, updatedAt: new Date() })
    .where(eq(products.id, id))
    .returning()
    .get();
}

export function deleteProduct(id: number): boolean {
  const result = db.delete(products).where(eq(products.id, id)).run();
  return result.changes > 0;
}

/**
 * Replace a product's evidence rows and qualification/messaging fields in one
 * transaction, so a partial save can never leave stale rows behind alongside
 * new ones.
 */
export function replaceEvidence(
  productId: number,
  rows: Array<Omit<ProductEvidence, 'id' | 'productId' | 'createdAt' | 'updatedAt' | 'position'>>,
  fields: Pick<
    NewProduct,
    | 'messagingTechnical'
    | 'messagingBusiness'
    | 'messagingExecutive'
    | 'messagingSafeClaim'
    | 'discovery'
    | 'buyingSignals'
    | 'redFlags'
    | 'proofRequired'
    | 'objections'
    | 'replacements'
    | 'learningChecklist'
  >,
): void {
  db.transaction(() => {
    db.delete(productEvidence).where(eq(productEvidence.productId, productId)).run();

    rows.forEach((row, position) => {
      db.insert(productEvidence)
        .values({ ...row, productId, position })
        .run();
    });

    db.update(products)
      .set({ ...fields, updatedAt: new Date() })
      .where(eq(products.id, productId))
      .run();
  }, { behavior: 'immediate' });
}

/** Coverage KPI: share of P1 products that are at least "Reviewed". */
/**
 * One labelled magnitude in a distribution.
 *
 * A type alias rather than an interface, deliberately: the chart components
 * take `Record<string, unknown>` (Recharts addresses fields by string key at
 * runtime), and TypeScript only considers object *type aliases* implicitly
 * compatible with an index signature -- an interface of the identical shape is
 * rejected, because interfaces are open to declaration merging and so cannot
 * be proven to have no extra incompatible members.
 */
export type PortfolioSlice = {
  name: string;
  value: number;
};

export interface PortfolioAnalytics {
  readonly total: number;
  readonly p1: number;
  readonly known: number;
  readonly verified: number;
  readonly coverage: number;
  /** P1/P2/P3 split. */
  readonly priorityMix: PortfolioSlice[];
  /** The four knowledge levels, in ladder order rather than by size. */
  readonly knowledgeLadder: PortfolioSlice[];
  /** Evidence confidence split. */
  readonly confidenceMix: PortfolioSlice[];
  /** Largest commercial categories, biggest first. */
  readonly topCategories: PortfolioSlice[];
}

/**
 * Catalog headline numbers plus the distributions behind them.
 *
 * One table scan feeds every figure. The counts were previously computed with
 * a separate `filter()` pass each, which is fine at 181 rows but meant adding
 * a chart implied adding another scan; grouping into a single reduce keeps the
 * cost flat as the visualisations grow.
 *
 * Ordering is deliberate per series: the knowledge ladder is returned in
 * progression order (To Learn -> Can Sell) because it reads as a funnel and
 * sorting it by size would destroy that; categories are sorted by size because
 * there is no inherent order to preserve.
 */
export function computeCoverage(): PortfolioAnalytics {
  const all = db.select().from(products).all();
  const total = all.length;

  const tally = <T extends string>(pick: (p: Product) => T): Map<T, number> => {
    const counts = new Map<T, number>();
    for (const product of all) {
      const key = pick(product);
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return counts;
  };

  const byPriority = tally((p) => p.priority);
  const byKnowledge = tally((p) => p.knowledge);
  const byConfidence = tally((p) => p.confidence);
  const byCategory = tally((p) => p.commercialCategory);

  const p1 = byPriority.get('P1') ?? 0;
  const known = byKnowledge.get('Can Sell') ?? 0;
  const verified = byConfidence.get('Verified') ?? 0;

  const p1Products = all.filter((p) => p.priority === 'P1');
  const p1Covered = p1Products.filter((p) => p.status !== 'Not Reviewed').length;
  const coverage = p1Products.length === 0 ? 0 : Math.round((p1Covered / p1Products.length) * 100);

  const inOrder = <T extends string>(order: readonly T[], counts: Map<T, number>): PortfolioSlice[] =>
    order.map((name) => ({ name, value: counts.get(name) ?? 0 }));

  return {
    total,
    p1,
    known,
    verified,
    coverage,
    priorityMix: inOrder(PRIORITIES, byPriority),
    knowledgeLadder: inOrder(KNOWLEDGE_LEVELS, byKnowledge),
    confidenceMix: inOrder(CONFIDENCE_LEVELS, byConfidence),
    topCategories: [...byCategory.entries()]
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 6),
  };
}

/** Find a product by exact, case-insensitive name -- used by the catalog sync. */
export function findProductByName(name: string): Product | undefined {
  return db
    .select()
    .from(products)
    .where(sql`lower(${products.product}) = lower(${name})`)
    .get();
}

export function findProductByUpstreamCode(code: string): Product | undefined {
  return db.select().from(products).where(eq(products.upstreamCode, code)).get();
}
