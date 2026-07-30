import 'server-only';

import { and, asc, desc, eq, like, or, sql } from 'drizzle-orm';

import { db } from '@/db/client';
import { productEvidence, products } from '@/db/schema';
import type { NewProduct, Product, ProductEvidence } from '@/db/schema';
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
  });
}

/** Coverage KPI: share of P1 products that are at least "Reviewed". */
export function computeCoverage(): { total: number; p1: number; known: number; verified: number; coverage: number } {
  const all = db.select().from(products).all();
  const total = all.length;
  const p1 = all.filter((p) => p.priority === 'P1').length;
  const known = all.filter((p) => p.knowledge === 'Can Sell').length;
  const verified = all.filter((p) => p.confidence === 'Verified').length;

  const p1Products = all.filter((p) => p.priority === 'P1');
  const p1Covered = p1Products.filter((p) => p.status !== 'Not Reviewed').length;
  const coverage = p1Products.length === 0 ? 0 : Math.round((p1Covered / p1Products.length) * 100);

  return { total, p1, known, verified, coverage };
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
