import { getTranslations } from 'next-intl/server';

import {
  COMMERCIAL_CATEGORIES,
  KNOWLEDGE_LEVELS,
  PRIORITIES,
  PRODUCT_STATUSES,
  SELL_MODES,
} from '@/domain/enums';
import { productFilterSchema } from '@/domain/schemas';
import { can } from '@/lib/auth/rbac';
import * as session from '@/lib/auth/session';
import { readToken } from '@/lib/security/csrf';
import { FilterForm } from '@/components/FilterForm';
import { computeCoverage, listCategories, listProducts } from '@/server/data/products';
import { getLastSyncRun } from '@/server/catalog/sync';
import { hasTencentCredentials } from '@/lib/env';

import { ProductsClient } from './ProductsClient';

export default async function ProductsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const active = await session.current();
  if (!active) return null; // (app) layout already redirects; satisfies the type checker.

  const raw = await searchParams;
  const filter = productFilterSchema.parse({
    q: raw.q,
    category: raw.category,
    commercial: raw.commercial,
    sellMode: raw.sellMode,
    priority: raw.priority,
    knowledge: raw.knowledge,
    status: raw.status,
    page: raw.page,
  });

  const [t, tCommon, list, categories, coverage, lastSync] = await Promise.all([
    getTranslations('products'),
    getTranslations('common'),
    Promise.resolve(listProducts(filter)),
    Promise.resolve(listCategories()),
    Promise.resolve(computeCoverage()),
    Promise.resolve(getLastSyncRun()),
  ]);

  const canWrite = can(active.user.role, 'catalog.write');
  const canDelete = can(active.user.role, 'catalog.delete');
  const canSync = can(active.user.role, 'catalog.sync');
  const canExport = can(active.user.role, 'data.export');
  const csrfToken = await readToken(active.sessionId);

  return (
    <>
      <div className="kpis">
        <div className="kpi">
          <span>{t('kpiTotal')}</span>
          <b>{coverage.total}</b>
        </div>
        <div className="kpi">
          <span>{t('kpiP1')}</span>
          <b>{coverage.p1}</b>
        </div>
        <div className="kpi">
          <span>{t('kpiKnown')}</span>
          <b>{coverage.known}</b>
        </div>
        <div className="kpi">
          <span>{t('kpiVerified')}</span>
          <b>{coverage.verified}</b>
        </div>
        <div className="kpi">
          <span>{t('kpiFiltered')}</span>
          <b>{list.total}</b>
        </div>
        <div className="kpi">
          <span>{t('kpiCoverage')}</span>
          <b>{coverage.coverage}%</b>
        </div>
      </div>

      <div className="workspace-banner">
        <div className="workspace-card">
          <h3>{t('bannerArchitectureTitle')}</h3>
          <p>{t('bannerArchitectureBody')}</p>
        </div>
        <div className="workspace-card">
          <h3>{t('bannerPrincipleTitle')}</h3>
          <p>{t('bannerPrincipleBody')}</p>
        </div>
      </div>

      <div className="grid-3" style={{ marginBottom: 14 }}>
        <div className="card">
          <h3>{t('cardInfrastructureTitle')}</h3>
          <p>{t('cardInfrastructureBody')}</p>
        </div>
        <div className="card">
          <h3>{t('cardStandaloneTitle')}</h3>
          <p>{t('cardStandaloneBody')}</p>
        </div>
        <div className="card">
          <h3>{t('cardStoryTitle')}</h3>
          <p>{t('cardStoryBody')}</p>
        </div>
      </div>

      <FilterForm>
        <input className="search" type="search" name="q" placeholder={t('searchPlaceholder')} defaultValue={filter.q} />
        <select name="commercial" defaultValue={filter.commercial}>
          <option value="">{t('filterCommercial')}</option>
          {COMMERCIAL_CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <select name="sellMode" defaultValue={filter.sellMode}>
          <option value="">{t('filterSellMode')}</option>
          {SELL_MODES.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <select name="category" defaultValue={filter.category}>
          <option value="">{t('filterCategory')}</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <select name="priority" defaultValue={filter.priority}>
          <option value="">{t('filterPriority')}</option>
          {PRIORITIES.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <select name="knowledge" defaultValue={filter.knowledge}>
          <option value="">{t('filterKnowledge')}</option>
          {KNOWLEDGE_LEVELS.map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
        <select name="status" defaultValue={filter.status}>
          <option value="">{t('filterStatus')}</option>
          {PRODUCT_STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <noscript>
          <button type="submit">{tCommon('filter')}</button>
        </noscript>
      </FilterForm>

      <ProductsClient
        items={list.items}
        total={list.total}
        page={list.page}
        pageSize={list.pageSize}
        canWrite={canWrite}
        canDelete={canDelete}
        canSync={canSync}
        canExport={canExport}
        csrfToken={csrfToken}
        syncStatus={
          lastSync
            ? { status: lastSync.status, finishedAt: lastSync.finishedAt?.toISOString() ?? null, sourceKind: lastSync.sourceKind }
            : null
        }
        hasTencentCredentials={hasTencentCredentials}
        filterQuery={Object.fromEntries(
          Object.entries({
            q: filter.q,
            category: filter.category,
            commercial: filter.commercial,
            sellMode: filter.sellMode,
            priority: filter.priority,
            knowledge: filter.knowledge,
            status: filter.status,
          }).filter(([, value]) => value !== ''),
        )}
      />
    </>
  );
}
