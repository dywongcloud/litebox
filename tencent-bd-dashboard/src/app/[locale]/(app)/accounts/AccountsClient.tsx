'use client';

import { useActionState, useEffect, useState } from 'react';
import { useTranslations } from 'next-intl';

import { ACCOUNT_FITS, ACCOUNT_SIZES, ACCOUNT_STAGES } from '@/domain/enums';
import type { Account } from '@/db/schema';
import { CSRF_FIELD } from '@/lib/security/csrf-constants';
import { Modal } from '@/components/Modal';
import { SelectField, TextAreaField, TextField } from '@/components/fields';
import { Link } from '@/i18n/navigation';
import { SubmitButton } from '@/components/SubmitButton';
import { removeAccount, saveAccount } from '@/server/actions/accounts';
import type { FormActionState } from '@/server/actions/shared';

const initialState: FormActionState = {};

function fitTone(fit: string): string {
  if (fit === 'High') return 'success';
  if (fit === 'Medium') return 'warn';
  return 'neutral';
}

export function AccountsClient({
  items,
  total,
  page,
  pageSize,
  canWrite,
  canDelete,
  csrfToken,
}: {
  items: Account[];
  total: number;
  page: number;
  pageSize: number;
  canWrite: boolean;
  canDelete: boolean;
  csrfToken: string;
}) {
  const t = useTranslations('accounts');
  const tCommon = useTranslations('common');
  const [modal, setModal] = useState<{ type: 'create' } | { type: 'edit'; account: Account } | null>(null);
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <>
      {canWrite ? (
        <div style={{ marginBottom: 10 }}>
          <button type="button" className="primary" onClick={() => setModal({ type: 'create' })}>
            {t('addAccount')}
          </button>
        </div>
      ) : null}

      <div className="table-wrap">
        <table className="account-table">
          <thead>
            <tr>
              <th>{t('colCompany')}</th>
              <th>{t('colRegion')}</th>
              <th>{t('colIndustry')}</th>
              <th>{t('colSize')}</th>
              <th>{t('colIncumbent')}</th>
              <th>{t('colProducts')}</th>
              <th>{t('colPain')}</th>
              <th>{t('colTrigger')}</th>
              <th>{t('colStage')}</th>
              <th>{t('colFit')}</th>
              <th>{t('colNext')}</th>
              <th>{t('colDue')}</th>
              <th>{tCommon('actions')}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((account) => (
              <tr key={account.id}>
                <td className="product-cell">
                  <Link href={`/accounts/${account.id}`}>{account.company}</Link>
                </td>
                <td>{account.region}</td>
                <td>{account.industry}</td>
                <td>{account.size}</td>
                <td title={account.incumbent}>{truncate(account.incumbent)}</td>
                <td title={account.products}>{truncate(account.products)}</td>
                <td title={account.pain}>{truncate(account.pain)}</td>
                <td title={account.trigger}>{truncate(account.trigger)}</td>
                <td>
                  <span className="pill" data-tone="brand">
                    {account.stage}
                  </span>
                </td>
                <td>
                  <span className="pill" data-tone={fitTone(account.fit)}>
                    {account.fit}
                  </span>
                </td>
                <td title={account.nextAction}>{truncate(account.nextAction)}</td>
                <td>{account.dueOn || '-'}</td>
                <td>
                  <div className="row">
                    {canWrite ? (
                      <button type="button" onClick={() => setModal({ type: 'edit', account })}>
                        {tCommon('edit')}
                      </button>
                    ) : null}
                    <Link href={`/accounts/${account.id}`} className="btn">
                      {t('openResearch')}
                    </Link>
                    {canDelete ? (
                      <form
                        action={async (formData) => {
                          await removeAccount(formData);
                        }}
                        onSubmit={(event) => {
                          if (!window.confirm(tCommon('confirmDelete'))) event.preventDefault();
                        }}
                      >
                        <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
                        <input type="hidden" name="id" value={account.id} />
                        <button type="submit" className="danger">
                          {tCommon('delete')}
                        </button>
                      </form>
                    ) : null}
                  </div>
                </td>
              </tr>
            ))}
            {items.length === 0 ? (
              <tr>
                <td colSpan={13} className="empty-state">
                  {tCommon('emptyState')}
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      {totalPages > 1 ? (
        <div className="row" style={{ marginTop: 12, justifyContent: 'space-between' }}>
          <span className="small">{tCommon('showing', { count: total === 0 ? 0 : (page - 1) * pageSize + 1, total })}</span>
          <span className="small">
            {page} / {totalPages}
          </span>
        </div>
      ) : null}

      {modal ? (
        <AccountFormModal
          account={modal.type === 'edit' ? modal.account : undefined}
          csrfToken={csrfToken}
          onClose={() => setModal(null)}
        />
      ) : null}
    </>
  );
}

function truncate(value: string, max = 80): string {
  const trimmed = value.trim();
  if (trimmed.length <= max) return trimmed || '-';
  return `${trimmed.slice(0, max)}...`;
}

function AccountFormModal({ account, csrfToken, onClose }: { account?: Account; csrfToken: string; onClose: () => void }) {
  const t = useTranslations('accounts');
  const tCommon = useTranslations('common');
  const [state, formAction] = useActionState(saveAccount, initialState);

  useEffect(() => {
    if (state.success) onClose();
  }, [state.success, onClose]);

  return (
    <Modal title={account ? t('editTitle') : t('createTitle')} onClose={onClose}>
      <div className="modal-header">
        <h2 style={{ margin: 0 }}>{account ? t('editTitle') : t('createTitle')}</h2>
        <button type="button" onClick={onClose}>
          {tCommon('close')}
        </button>
      </div>

      {state.message ? (
        <p className="form-message" data-tone="error" role="alert">
          {state.message}
        </p>
      ) : null}

      <form action={formAction} id="account-form">
        <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
        {account ? <input type="hidden" name="id" value={account.id} /> : null}

        <div className="form-grid">
          <TextField label={t('fieldCompany')} name="company" defaultValue={account?.company} errors={state.errors} required />
          <TextField label={t('fieldRegion')} name="region" defaultValue={account?.region} />
          <TextField label={t('fieldIndustry')} name="industry" defaultValue={account?.industry} />
          <SelectField label={t('fieldSize')} name="size" defaultValue={account?.size ?? 'Scale-up'} options={ACCOUNT_SIZES} />
          <SelectField label={t('fieldStage')} name="stage" defaultValue={account?.stage ?? 'Target'} options={ACCOUNT_STAGES} />
          <SelectField label={t('fieldFit')} name="fit" defaultValue={account?.fit ?? 'Medium'} options={ACCOUNT_FITS} />
          <TextField label={t('fieldContact')} name="contact" defaultValue={account?.contact} />
          <TextField label={t('fieldDue')} name="dueOn" type="date" defaultValue={account?.dueOn} />

          <TextAreaField label={t('fieldIncumbent')} name="incumbent" defaultValue={account?.incumbent} />
          <TextAreaField label={t('fieldProducts')} name="products" defaultValue={account?.products} />
          <TextAreaField label={t('fieldPain')} name="pain" defaultValue={account?.pain} />
          <TextAreaField label={t('fieldTrigger')} name="trigger" defaultValue={account?.trigger} />
          <TextAreaField label={t('fieldPath')} name="path" defaultValue={account?.path} />
          <TextAreaField label={t('fieldNext')} name="nextAction" defaultValue={account?.nextAction} />
          <TextAreaField className="full" label={t('fieldNotes')} name="notes" defaultValue={account?.notes} />
        </div>
      </form>

      <div className="modal-footer">
        <button type="button" onClick={onClose}>
          {tCommon('cancel')}
        </button>
        <SubmitButton form="account-form" className="primary" pendingLabel={tCommon('saving')}>
          {tCommon('save')}
        </SubmitButton>
      </div>
    </Modal>
  );
}
