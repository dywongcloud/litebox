'use client';

import { useActionState, useEffect, useState } from 'react';
import { useTranslations } from 'next-intl';

import {
  KNOWLEDGE_LEVELS,
  PRIORITIES,
  PRIORITY_SCORE_MAX,
  PRIORITY_SCORE_MIN,
  CONFIDENCE_LEVELS,
  PRODUCT_STATUSES,
  COMMERCIAL_CATEGORIES,
  SELL_MODES,
  EVIDENCE_LEVELS,
  CAN_SAY_OPTIONS,
  EVIDENCE_CONFIDENCE,
} from '@/domain/enums';
import type { Product, ProductEvidence } from '@/db/schema';
import { CSRF_FIELD } from '@/lib/security/csrf-constants';
import { Link } from '@/i18n/navigation';
import { BookOpen, FlaskConical, Gauge, MoreHorizontal, Pencil } from 'lucide-react';

import { ConfirmButton } from '@/components/ConfirmButton';
import { Modal } from '@/components/Modal';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { TruncatedCell } from '@/components/ui/tooltip';
import { SelectField, TextAreaField, TextField } from '@/components/fields';
import { SubmitButton } from '@/components/SubmitButton';
import { TranslateField } from '@/components/TranslateField';
import { useToast } from '@/components/ui/toast';
import {
  exportProductsCsv,
  removeProduct,
  runCatalogSync,
  saveEvidenceStudio,
  savePriorityScore,
  saveProduct,
  saveProductStory,
} from '@/server/actions/products';
import { loadProductEvidence } from '@/server/actions/read';
import type { FormActionState } from '@/server/actions/shared';

type ModalState =
  | { type: 'create' }
  | { type: 'edit'; product: Product }
  | { type: 'story'; product: Product }
  | { type: 'score'; product: Product }
  | { type: 'evidence'; product: Product };

const initialState: FormActionState = {};

function priorityTone(priority: string): string {
  if (priority === 'P1') return 'danger';
  if (priority === 'P2') return 'warn';
  return 'brand';
}

export function ProductsClient({
  items,
  total,
  page,
  pageSize,
  canWrite,
  canDelete,
  canSync,
  canExport,
  csrfToken,
  syncStatus,
  hasTencentCredentials,
  filterQuery,
}: {
  items: Product[];
  total: number;
  page: number;
  pageSize: number;
  canWrite: boolean;
  canDelete: boolean;
  canSync: boolean;
  canExport: boolean;
  csrfToken: string;
  syncStatus: { status: string; finishedAt: string | null; sourceKind: string } | null;
  hasTencentCredentials: boolean;
  filterQuery: Record<string, string>;
}) {
  const t = useTranslations('products');
  const tCommon = useTranslations('common');
  const [modal, setModal] = useState<ModalState | null>(null);
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <>
      <div className="spread" style={{ marginBottom: 10 }}>
        <div className="row">
          {canWrite ? (
            <button type="button" className="primary" onClick={() => setModal({ type: 'create' })}>
              {t('addProduct')}
            </button>
          ) : null}
          {canSync ? <SyncButton csrfToken={csrfToken} t={t} /> : null}
          {canExport ? <ExportCsvButton csrfToken={csrfToken} filterQuery={filterQuery} t={t} /> : null}
        </div>
        <span className="small">
          {syncStatus
            ? t('syncLast', { when: syncStatus.finishedAt ? new Date(syncStatus.finishedAt).toLocaleString() : '-', source: syncStatus.sourceKind })
            : t('syncNever')}
          {!hasTencentCredentials ? ` · ${t('syncUnavailable')}` : ''}
        </span>
      </div>

      <div className="table-wrap" data-responsive>
        <table>
          <thead>
            <tr>
              <th>{t('colPriority')}</th>
              <th>{t('colCommercial')}</th>
              <th>{t('colProduct')}</th>
              <th>{t('colCategory')}</th>
              <th>{t('colStory')}</th>
              <th>{t('colCompetitors')}</th>
              <th>{t('colPainPoints')}</th>
              <th>{t('colKnowledge')}</th>
              <th>{t('colConfidence')}</th>
              <th>{t('colStatus')}</th>
              <th>{tCommon('actions')}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((product) => (
              <tr key={product.id}>
                <td>
                  <span className="pill" data-tone={priorityTone(product.priority)}>
                    {product.priority}
                  </span>
                </td>
                <td>{product.commercialCategory}</td>
                <td className="product-cell">{product.product}</td>
                <td>{product.category}</td>
                {/* `title` gave a ~1s unstyled browser tooltip with no touch
                    or screen-reader equivalent; `TruncatedCell` is a real
                    Radix tooltip wired to the trigger's `aria-describedby`
                    and reachable by keyboard. */}
                <td>
                  <TruncatedCell value={product.solutionStory} />
                </td>
                <td>
                  <TruncatedCell value={product.competitors} />
                </td>
                <td>
                  <TruncatedCell value={product.painPoints} />
                </td>
                <td>{product.knowledge}</td>
                <td>{product.confidence}</td>
                <td>{product.status}</td>
                <td>
                  <ProductRowActions
                    product={product}
                    canWrite={canWrite}
                    canDelete={canDelete}
                    csrfToken={csrfToken}
                    setModal={setModal}
                  />
                </td>
              </tr>
            ))}
            {items.length === 0 ? (
              <tr>
                <td colSpan={11} className="empty-state">
                  {tCommon('emptyState')}
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>

        <div className="responsive-cards">
          {items.map((product) => (
            <div className="data-card" key={product.id}>
              <div className="row" style={{ justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
                <span className="pill" data-tone={priorityTone(product.priority)}>
                  {product.priority}
                </span>
                <span className="pill" data-tone="neutral">
                  {product.status}
                </span>
              </div>
              <div className="data-card-title">{product.product}</div>
              <dl>
                <div className="data-card-row">
                  <dt>{t('colCommercial')}</dt>
                  <dd>{product.commercialCategory}</dd>
                </div>
                <div className="data-card-row">
                  <dt>{t('colKnowledge')}</dt>
                  <dd>{product.knowledge}</dd>
                </div>
                <div className="data-card-row">
                  <dt>{t('colStory')}</dt>
                  <dd>{truncate(product.solutionStory, 90)}</dd>
                </div>
              </dl>
              <div className="data-card-actions">
                <ProductRowActions
                  product={product}
                  canWrite={canWrite}
                  canDelete={canDelete}
                  csrfToken={csrfToken}
                  setModal={setModal}
                />
              </div>
            </div>
          ))}
          {items.length === 0 ? <p className="empty-state">{tCommon('emptyState')}</p> : null}
        </div>
      </div>

      <Pagination page={page} totalPages={totalPages} total={total} pageSize={pageSize} filterQuery={filterQuery} tCommon={tCommon} />

      {modal?.type === 'create' || modal?.type === 'edit' ? (
        <ProductFormModal
          product={modal.type === 'edit' ? modal.product : undefined}
          csrfToken={csrfToken}
          onClose={() => setModal(null)}
        />
      ) : null}
      {modal?.type === 'story' ? (
        <StoryModal product={modal.product} csrfToken={csrfToken} onClose={() => setModal(null)} />
      ) : null}
      {modal?.type === 'score' ? (
        <ScoreModal product={modal.product} csrfToken={csrfToken} onClose={() => setModal(null)} />
      ) : null}
      {modal?.type === 'evidence' ? (
        <EvidenceModal product={modal.product} csrfToken={csrfToken} onClose={() => setModal(null)} />
      ) : null}
    </>
  );
}

function truncate(value: string, max: number): string {
  const trimmed = value.trim();
  if (trimmed.length <= max) return trimmed || '-';
  return `${trimmed.slice(0, max)}...`;
}

function Pagination({
  page,
  totalPages,
  total,
  pageSize,
  filterQuery,
  tCommon,
}: {
  page: number;
  totalPages: number;
  total: number;
  pageSize: number;
  filterQuery: Record<string, string>;
  tCommon: ReturnType<typeof useTranslations>;
}) {
  if (totalPages <= 1) return null;

  // Built from server-known state (the parsed filter, passed down as a prop)
  // rather than `window.location`, which does not exist during the initial
  // server render of this client component.
  const queryFor = (p: number) => ({ ...filterQuery, page: String(p) });

  return (
    <div className="row" style={{ marginTop: 12, justifyContent: 'space-between' }}>
      <span className="small">{tCommon('showing', { count: total === 0 ? 0 : (page - 1) * pageSize + 1, total })}</span>
      <div className="row">
        {page > 1 ? (
          <Link className="btn" href={{ pathname: '/products', query: queryFor(page - 1) }}>
            {tCommon('previousPage')}
          </Link>
        ) : (
          <span className="btn" aria-disabled="true">
            {tCommon('previousPage')}
          </span>
        )}
        <span className="small">
          {page} / {totalPages}
        </span>
        {page < totalPages ? (
          <Link className="btn" href={{ pathname: '/products', query: queryFor(page + 1) }}>
            {tCommon('nextPage')}
          </Link>
        ) : (
          <span className="btn" aria-disabled="true">
            {tCommon('nextPage')}
          </span>
        )}
      </div>
    </div>
  );
}

/**
 * The row-action menu, shared between the table row and its responsive
 * card-list counterpart -- one definition, so a permission change or a new
 * action never needs updating in two places that could drift apart.
 *
 * Collapsed behind a single trigger rather than rendered as four inline
 * buttons: at forty rows that was ~200 competing targets and made Actions the
 * widest column on the page. The menu also gives each action a full label
 * instead of the abbreviations the inline buttons had to use to fit.
 */
function ProductRowActions({
  product,
  canWrite,
  canDelete,
  csrfToken,
  setModal,
}: {
  product: Product;
  canWrite: boolean;
  canDelete: boolean;
  csrfToken: string;
  setModal: (state: ModalState) => void;
}) {
  const t = useTranslations('products');
  const tCommon = useTranslations('common');

  if (!canWrite && !canDelete) return null;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label={tCommon('actions')}>
          <MoreHorizontal />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent>
        {canWrite ? (
          <>
            <DropdownMenuItem onSelect={() => setModal({ type: 'edit', product })}>
              <Pencil />
              {tCommon('edit')}
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => setModal({ type: 'evidence', product })}>
              <FlaskConical />
              {t('openEvidence')}
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => setModal({ type: 'story', product })}>
              <BookOpen />
              {t('openStory')}
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => setModal({ type: 'score', product })}>
              <Gauge />
              {t('openScore')}
            </DropdownMenuItem>
          </>
        ) : null}
        {canWrite && canDelete ? <DropdownMenuSeparator /> : null}
        {canDelete ? (
          // Rendered outside a `DropdownMenuItem`: the delete flow is a form
          // POST with a two-step confirm, and an item would close the menu on
          // the first click before the confirm could ever be shown.
          <div className="px-1 py-0.5">
            <DeleteProductButton id={product.id} csrfToken={csrfToken} label={tCommon('delete')} />
          </div>
        ) : null}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function DeleteProductButton({ id, csrfToken, label }: { id: number; csrfToken: string; label: string }) {
  return (
    <form
      action={async (formData) => {
        await removeProduct(formData);
      }}
    >
      <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
      <input type="hidden" name="id" value={id} />
      <ConfirmButton label={label} />
    </form>
  );
}

function ExportCsvButton({
  csrfToken,
  filterQuery,
  t,
}: {
  csrfToken: string;
  filterQuery: Record<string, string>;
  t: ReturnType<typeof useTranslations>;
}) {
  const toast = useToast();
  const [exporting, setExporting] = useState(false);

  async function handleExport() {
    setExporting(true);
    try {
      const formData = new FormData();
      formData.set(CSRF_FIELD, csrfToken);
      for (const [key, value] of Object.entries(filterQuery)) {
        formData.set(key, value);
      }
      const result = await exportProductsCsv(formData);
      if (!result.ok || !result.csv) {
        toast.show(result.message ?? 'Export failed.', 'error');
        return;
      }
      // Prefix with a UTF-8 BOM: Excel on Windows otherwise guesses the
      // system codepage and mangles CJK product names on open.
      const blob = new Blob(['﻿', result.csv], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `product-catalog-${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.show(`Exported ${result.count ?? 0} products.`, 'success');
    } finally {
      setExporting(false);
    }
  }

  return (
    <button type="button" onClick={handleExport} disabled={exporting}>
      {exporting ? t('exportingCsv') : t('exportCsv')}
    </button>
  );
}

function SyncButton({ csrfToken, t }: { csrfToken: string; t: ReturnType<typeof useTranslations> }) {
  const [state, formAction] = useActionState(runCatalogSync, initialState);
  return (
    <form action={formAction}>
      <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
      <SubmitButton pendingLabel={t('syncRunning')}>{t('syncCatalog')}</SubmitButton>
      {state.message ? (
        <span className="small" style={{ marginLeft: 8 }} role="status">
          {state.message}
        </span>
      ) : null}
    </form>
  );
}

// ---------------------------------------------------------------------------
// Create / edit product
// ---------------------------------------------------------------------------

function ProductFormModal({ product, csrfToken, onClose }: { product?: Product; csrfToken: string; onClose: () => void }) {
  const t = useTranslations('products');
  const tCommon = useTranslations('common');
  const [state, formAction] = useActionState(saveProduct, initialState);

  useEffect(() => {
    if (state.success) onClose();
  }, [state.success, onClose]);

  return (
    <Modal title={product ? t('editTitle') : t('createTitle')} onClose={onClose}>
      <div className="modal-header">
        <h2 style={{ margin: 0 }}>{product ? t('editTitle') : t('createTitle')}</h2>
        <button type="button" onClick={onClose}>
          {tCommon('close')}
        </button>
      </div>

      {state.message ? (
        <p className="form-message" data-tone="error" role="alert">
          {state.message}
        </p>
      ) : null}

      <form action={formAction} id="product-form">
        <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
        {product ? <input type="hidden" name="id" value={product.id} /> : null}

        <div className="form-grid">
          <TextField label={t('fieldCategory')} name="category" defaultValue={product?.category} errors={state.errors} />
          <TextField label={t('fieldProduct')} name="product" defaultValue={product?.product} errors={state.errors} required />

          <SelectField label={t('fieldPriority')} name="priority" defaultValue={product?.priority ?? 'P3'} options={PRIORITIES} />
          <SelectField label={t('fieldKnowledge')} name="knowledge" defaultValue={product?.knowledge ?? 'To Learn'} options={KNOWLEDGE_LEVELS} />
          <SelectField label={t('fieldConfidence')} name="confidence" defaultValue={product?.confidence ?? 'Hypothesis'} options={CONFIDENCE_LEVELS} />
          <SelectField label={t('fieldStatus')} name="status" defaultValue={product?.status ?? 'Not Reviewed'} options={PRODUCT_STATUSES} />

          <div className="full">
            <TextAreaField label={t('fieldDescription')} name="description" defaultValue={product?.description} errors={state.errors} />
            {product ? (
              <TranslateField entityType="product" entityId={product.id} field="description" sourceLocale="en" csrfToken={csrfToken} />
            ) : null}
          </div>
          <TextAreaField label={t('fieldCompetitors')} name="competitors" defaultValue={product?.competitors} />
          <TextAreaField label={t('fieldUseCases')} name="useCases" defaultValue={product?.useCases} />
          <TextAreaField label={t('fieldIndustries')} name="industries" defaultValue={product?.industries} />
          <TextField label={t('fieldCompanySize')} name="companySize" defaultValue={product?.companySize} />
          <TextAreaField label={t('fieldCustomerGate')} name="customerGate" defaultValue={product?.customerGate} />
          <TextAreaField label={t('fieldPainPoints')} name="painPoints" defaultValue={product?.painPoints} />
          <TextAreaField label={t('fieldStrengths')} name="strengths" defaultValue={product?.strengths} />
          <TextAreaField label={t('fieldWeaknesses')} name="weaknesses" defaultValue={product?.weaknesses} />
          <TextAreaField label={t('fieldProductEntry')} name="productEntry" defaultValue={product?.productEntry} />
          <TextAreaField className="full" label={t('fieldBdMotion')} name="bdMotion" defaultValue={product?.bdMotion} />
          <TextAreaField className="full" label={t('fieldNotes')} name="notes" defaultValue={product?.notes} />
        </div>
      </form>

      <div className="modal-footer">
        <button type="button" onClick={onClose}>
          {tCommon('cancel')}
        </button>
        <SubmitButton form="product-form" className="primary" pendingLabel={tCommon('saving')}>
          {tCommon('save')}
        </SubmitButton>
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Solution story
// ---------------------------------------------------------------------------

function StoryModal({ product, csrfToken, onClose }: { product: Product; csrfToken: string; onClose: () => void }) {
  const t = useTranslations('story');
  const tCommon = useTranslations('common');
  const [state, formAction] = useActionState(saveProductStory, initialState);

  useEffect(() => {
    if (state.success) onClose();
  }, [state.success, onClose]);

  return (
    <Modal title={t('title')} onClose={onClose}>
      <div className="modal-header">
        <div>
          <h2 style={{ margin: 0 }}>{t('title')}</h2>
          <p className="small">{t('subtitle')}</p>
        </div>
        <button type="button" onClick={onClose}>
          {tCommon('close')}
        </button>
      </div>

      {state.message ? (
        <p className="form-message" data-tone="error" role="alert">
          {state.message}
        </p>
      ) : null}

      <form action={formAction} id="story-form">
        <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
        <input type="hidden" name="id" value={product.id} />
        <div className="form-grid">
          <SelectField label={t('commercialCategory')} name="commercialCategory" defaultValue={product.commercialCategory} options={COMMERCIAL_CATEGORIES} />
          <SelectField label={t('sellMode')} name="sellMode" defaultValue={product.sellMode} options={SELL_MODES} />
          <TextField label={t('primaryCompetitor')} name="primaryCompetitor" defaultValue={product.primaryCompetitor} />
          <TextAreaField label={t('useCases')} name="useCases" defaultValue={product.useCases} />
          <TextAreaField label={t('referenceCustomers')} name="referenceCustomers" defaultValue={product.referenceCustomers} hint={t('referenceCustomersHint')} />
          <TextAreaField label={t('tencentEdge')} name="tencentEdge" defaultValue={product.tencentEdge} />
          <div className="full">
            <TextAreaField label={t('solutionStory')} name="solutionStory" defaultValue={product.solutionStory} />
            <TranslateField entityType="product" entityId={product.id} field="solutionStory" sourceLocale="en" csrfToken={csrfToken} />
          </div>
        </div>
        <div className="card" style={{ marginTop: 12, background: 'var(--dark)', color: 'white', borderColor: 'transparent' }}>
          <b>{t('formulaTitle')}</b>
          <p style={{ color: '#c7d3e6' }}>{t('formulaBody')}</p>
        </div>
      </form>

      <div className="modal-footer">
        <button type="button" onClick={onClose}>
          {tCommon('cancel')}
        </button>
        <SubmitButton form="story-form" className="primary" pendingLabel={tCommon('saving')}>
          {t('save')}
        </SubmitButton>
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Priority scorecard
// ---------------------------------------------------------------------------

const SCORE_DIMENSIONS = [
  { key: 'demand', field: 'scoreDemand' as const },
  { key: 'rightToWin', field: 'scoreRightToWin' as const },
  { key: 'entry', field: 'scoreEntry' as const },
  { key: 'poc', field: 'scorePoc' as const },
  { key: 'expansion', field: 'scoreExpansion' as const },
  { key: 'revenue', field: 'scoreRevenue' as const },
];

function ScoreModal({ product, csrfToken, onClose }: { product: Product; csrfToken: string; onClose: () => void }) {
  const t = useTranslations('priority');
  const tCommon = useTranslations('common');
  const [state, formAction] = useActionState(savePriorityScore, initialState);
  const [scores, setScores] = useState<Record<string, number>>(
    Object.fromEntries(SCORE_DIMENSIONS.map((d) => [d.key, product[d.field]])),
  );

  useEffect(() => {
    if (state.success) onClose();
  }, [state.success, onClose]);

  const total = Object.values(scores).reduce((sum, v) => sum + v, 0);
  const max = SCORE_DIMENSIONS.length * PRIORITY_SCORE_MAX;
  const recommendation = total >= max * 0.8 ? 'P1' : total >= max * 0.55 ? 'P2' : 'P3';

  return (
    <Modal title={t('title')} onClose={onClose}>
      <div className="modal-header">
        <div>
          <h2 style={{ margin: 0 }}>{t('title')}</h2>
          <p className="small">{t('subtitle')}</p>
        </div>
        <button type="button" onClick={onClose}>
          {tCommon('close')}
        </button>
      </div>

      {state.message ? (
        <p className="form-message" data-tone="error" role="alert">
          {state.message}
        </p>
      ) : null}

      <form action={formAction} id="score-form">
        <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
        <input type="hidden" name="id" value={product.id} />

        <div className="grid-3" style={{ marginBottom: 12 }}>
          {SCORE_DIMENSIONS.map((d) => (
            <label key={d.key}>
              {t(d.key as 'demand')}
              <input
                type="number"
                name={d.key}
                min={PRIORITY_SCORE_MIN}
                max={PRIORITY_SCORE_MAX}
                value={scores[d.key]}
                onChange={(e) => setScores((s) => ({ ...s, [d.key]: Number(e.target.value) }))}
              />
              <span className="small">{t(`${d.key}Hint` as 'demandHint')}</span>
            </label>
          ))}
        </div>

        <div className="spread card" style={{ background: 'var(--dark)', color: 'white', borderColor: 'transparent' }}>
          <div>
            <div>{t('total')}</div>
            <span className="small" style={{ color: '#c7d3e6' }}>
              {t('totalHint')}
            </span>
          </div>
          <strong style={{ fontSize: 24 }}>
            {total} / {max}
          </strong>
          <span className="pill" data-tone={priorityTone(recommendation)}>
            {recommendation}
          </span>
        </div>

        <div className="stack" style={{ marginTop: 12 }}>
          <TextAreaField label={t('rationale')} name="rationale" defaultValue={product.scoreRationale} hint={t('rationaleHint')} />
          <TextAreaField label={t('validation')} name="validation" defaultValue={product.scoreValidation} hint={t('validationHint')} />
        </div>
      </form>

      <div className="modal-footer">
        <button type="button" onClick={onClose}>
          {tCommon('cancel')}
        </button>
        <SubmitButton form="score-form" className="primary" pendingLabel={tCommon('saving')}>
          {t('save')}
        </SubmitButton>
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Evidence Studio
// ---------------------------------------------------------------------------

type EvidenceRowDraft = Pick<
  ProductEvidence,
  'level' | 'statement' | 'canSay' | 'source' | 'confidence' | 'verifiedOn' | 'notes'
>;

function blankEvidenceRow(): EvidenceRowDraft {
  return { level: 'Assumption', statement: '', canSay: 'No', source: '', confidence: 'Low', verifiedOn: '', notes: '' };
}

function EvidenceModal({ product, csrfToken, onClose }: { product: Product; csrfToken: string; onClose: () => void }) {
  const t = useTranslations('evidence');
  const tCommon = useTranslations('common');
  const [state, formAction] = useActionState(saveEvidenceStudio, initialState);
  const [rows, setRows] = useState<EvidenceRowDraft[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    loadProductEvidence(product.id).then((result) => {
      if (cancelled) return;
      if (result.ok && result.rows) {
        setRows(
          result.rows.map((r) => ({
            level: r.level,
            statement: r.statement,
            canSay: r.canSay,
            source: r.source,
            confidence: r.confidence,
            verifiedOn: r.verifiedOn,
            notes: r.notes,
          })),
        );
      } else {
        setLoadError(result.message ?? 'Failed to load evidence.');
      }
    });
    return () => {
      cancelled = true;
    };
  }, [product.id]);

  useEffect(() => {
    if (state.success) onClose();
  }, [state.success, onClose]);

  const verifiedCount = (rows ?? []).filter((r) => r.canSay === 'Yes').length;

  return (
    <Modal title={t('title')} onClose={onClose} wide>
      <div className="modal-header">
        <div>
          <h2 style={{ margin: 0 }}>{t('title')}</h2>
          <p className="small">{t('subtitle')}</p>
        </div>
        <button type="button" onClick={onClose}>
          {tCommon('close')}
        </button>
      </div>

      {state.message ? (
        <p className="form-message" data-tone="error" role="alert">
          {state.message}
        </p>
      ) : null}

      <div className="claim-guide">
        <div className="claim-card" style={{ background: 'var(--success-bg)' }}>
          <b>{t('guideFactTitle')}</b>
          <p>{t('guideFactBody')}</p>
        </div>
        <div className="claim-card" style={{ background: 'var(--soft)' }}>
          <b>{t('guideInferenceTitle')}</b>
          <p>{t('guideInferenceBody')}</p>
        </div>
        <div className="claim-card" style={{ background: 'var(--danger-bg)' }}>
          <b>{t('guideOutcomeTitle')}</b>
          <p>{t('guideOutcomeBody')}</p>
        </div>
      </div>

      {rows === null ? (
        <p className="small">{loadError ?? tCommon('loading')}</p>
      ) : (
        <form action={formAction} id="evidence-form">
          <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
          <input type="hidden" name="id" value={product.id} />
          <input type="hidden" name="rows" value={JSON.stringify(rows)} />

          <div className="evidence-section">
            <div className="spread">
              <h3 style={{ margin: 0 }}>{t('tableTitle')}</h3>
              <span className="small">{t('summary', { verified: verifiedCount, total: rows.length })}</span>
            </div>
            <p className="hint small">{t('tableHint')}</p>

            {rows.map((row, index) => (
              <div className="evidence-row" key={index}>
                <select value={row.level} onChange={(e) => updateRow(setRows, index, { level: e.target.value as EvidenceRowDraft['level'] })}>
                  {EVIDENCE_LEVELS.map((level) => (
                    <option key={level} value={level}>
                      {level}
                    </option>
                  ))}
                </select>
                <textarea value={row.statement} onChange={(e) => updateRow(setRows, index, { statement: e.target.value })} />
                <select value={row.canSay} onChange={(e) => updateRow(setRows, index, { canSay: e.target.value as EvidenceRowDraft['canSay'] })}>
                  {CAN_SAY_OPTIONS.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
                <textarea value={row.source} onChange={(e) => updateRow(setRows, index, { source: e.target.value })} />
                <select value={row.confidence} onChange={(e) => updateRow(setRows, index, { confidence: e.target.value as EvidenceRowDraft['confidence'] })}>
                  {EVIDENCE_CONFIDENCE.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
                <input type="date" value={row.verifiedOn} onChange={(e) => updateRow(setRows, index, { verifiedOn: e.target.value })} />
                <button type="button" className="danger" onClick={() => setRows((r) => (r ?? []).filter((_, i) => i !== index))} aria-label={tCommon('delete')}>
                  x
                </button>
              </div>
            ))}

            <button type="button" onClick={() => setRows((r) => [...(r ?? []), blankEvidenceRow()])} style={{ marginTop: 10 }}>
              {t('addRow')}
            </button>
          </div>

          <div className="evidence-section">
            <h3>{t('messagingTitle')}</h3>
            <div className="two-col grid-2">
              <TextAreaField label={t('technical')} name="messagingTechnical" defaultValue={product.messagingTechnical} hint={t('technicalHint')} />
              <TextAreaField label={t('business')} name="messagingBusiness" defaultValue={product.messagingBusiness} hint={t('businessHint')} />
              <TextAreaField label={t('executive')} name="messagingExecutive" defaultValue={product.messagingExecutive} hint={t('executiveHint')} />
              <TextAreaField label={t('safeClaim')} name="messagingSafeClaim" defaultValue={product.messagingSafeClaim} hint={t('safeClaimHint')} />
            </div>
          </div>

          <div className="evidence-section">
            <h3>{t('qualificationTitle')}</h3>
            <div className="grid-2">
              <TextAreaField label={t('discovery')} name="discovery" defaultValue={product.discovery} hint={t('discoveryHint')} />
              <TextAreaField label={t('signals')} name="buyingSignals" defaultValue={product.buyingSignals} hint={t('signalsHint')} />
              <TextAreaField label={t('redFlags')} name="redFlags" defaultValue={product.redFlags} hint={t('redFlagsHint')} />
              <TextAreaField label={t('proofRequired')} name="proofRequired" defaultValue={product.proofRequired} hint={t('proofRequiredHint')} />
              <TextAreaField label={t('objections')} name="objections" defaultValue={product.objections} hint={t('objectionsHint')} />
              <TextAreaField label={t('replacements')} name="replacements" defaultValue={product.replacements} hint={t('replacementsHint')} />
              <TextAreaField className="full" label={t('learning')} name="learningChecklist" defaultValue={product.learningChecklist} hint={t('learningHint')} />
            </div>
          </div>
        </form>
      )}

      <div className="modal-footer">
        <button type="button" onClick={onClose}>
          {tCommon('cancel')}
        </button>
        <SubmitButton form="evidence-form" className="primary" pendingLabel={tCommon('saving')} disabled={rows === null}>
          {t('save')}
        </SubmitButton>
      </div>
    </Modal>
  );
}

function updateRow(
  setRows: React.Dispatch<React.SetStateAction<EvidenceRowDraft[] | null>>,
  index: number,
  patch: Partial<EvidenceRowDraft>,
) {
  setRows((rows) => (rows ?? []).map((row, i) => (i === index ? { ...row, ...patch } : row)));
}

