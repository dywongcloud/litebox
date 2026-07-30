import 'server-only';

import { desc, eq } from 'drizzle-orm';

import { db } from '@/db/client';
import { catalogSyncRuns, products } from '@/db/schema';
import { hasTencentCredentials } from '@/lib/env';
import { findProductByName, findProductByUpstreamCode } from '@/server/data/products';
import { fetchUpstreamCatalog } from '@/server/tencent/catalog-client';

export interface SyncOutcome {
  readonly ok: boolean;
  readonly runId: number;
  readonly seen: number;
  readonly created: number;
  readonly updated: number;
  readonly error?: string;
}

/**
 * Synchronise the local product table against the upstream Tencent Cloud
 * product catalog (see `@/server/tencent/catalog-client` for which API and
 * why).
 *
 * The merge is deliberately non-destructive:
 *
 *   - An upstream code already attached to a local row: leave the row alone.
 *     A rep may have spent real effort on its BD fields; a sync must never
 *     clobber that with upstream metadata, which carries none of it.
 *   - An upstream item matching an existing row by name (case-insensitively)
 *     that has no code yet: attach the code and stamp `upstreamSyncedAt`.
 *     This is a linking operation, not a content update.
 *   - No match at all: insert a minimal stub row (`category` empty,
 *     `status: 'Not Reviewed'`) so the product enters the intelligence queue
 *     with an authoritative name and code. It carries no BD fields because
 *     the API has none to offer -- filling them in is exactly this tool's job.
 *
 * Every run is recorded in `catalog_sync_runs`, successful or not, so a
 * silent, permanent upstream failure is visible in the admin panel rather than
 * invisible.
 */
export async function syncCatalog(triggeredBy: number): Promise<SyncOutcome> {
  if (!hasTencentCredentials) {
    const run = db
      .insert(catalogSyncRuns)
      .values({
        status: 'failed',
        sourceKind: 'local-corpus',
        error: 'Tencent Cloud credentials are not configured',
        triggeredBy,
        finishedAt: new Date(),
      })
      .returning({ id: catalogSyncRuns.id })
      .get();

    return { ok: false, runId: run.id, seen: 0, created: 0, updated: 0, error: 'not-configured' };
  }

  const run = db
    .insert(catalogSyncRuns)
    .values({ status: 'running', sourceKind: 'tencent-api', triggeredBy })
    .returning({ id: catalogSyncRuns.id })
    .get();

  const result = await fetchUpstreamCatalog();

  if (!result.ok) {
    db.update(catalogSyncRuns)
      .set({ status: 'failed', error: `${result.code}: ${result.message}`, finishedAt: new Date() })
      .where(eq(catalogSyncRuns.id, run.id))
      .run();

    return { ok: false, runId: run.id, seen: 0, created: 0, updated: 0, error: result.message };
  }

  let created = 0;
  let updated = 0;

  db.transaction(() => {
    for (const item of result.data) {
      const byCode = findProductByUpstreamCode(item.code);
      if (byCode) continue;

      const byName = findProductByName(item.name);
      if (byName) {
        db.update(products)
          .set({ upstreamCode: item.code, upstreamSyncedAt: new Date(), updatedAt: new Date() })
          .where(eq(products.id, byName.id))
          .run();
        updated++;
        continue;
      }

      db.insert(products)
        .values({
          category: '',
          product: item.name,
          upstreamCode: item.code,
          upstreamSyncedAt: new Date(),
          source: 'Tencent Cloud Billing API (DescribeProducts)',
        })
        .run();
      created++;
    }
  });

  db.update(catalogSyncRuns)
    .set({
      status: 'success',
      productsSeen: result.data.length,
      productsCreated: created,
      productsUpdated: updated,
      finishedAt: new Date(),
    })
    .where(eq(catalogSyncRuns.id, run.id))
    .run();

  return { ok: true, runId: run.id, seen: result.data.length, created, updated };
}

export function getLastSyncRun() {
  return db.select().from(catalogSyncRuns).orderBy(desc(catalogSyncRuns.startedAt)).limit(1).get();
}
