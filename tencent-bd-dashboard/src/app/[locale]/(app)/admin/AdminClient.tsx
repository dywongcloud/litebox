'use client';

import { useActionState, useEffect, useState } from 'react';
import { useTranslations } from 'next-intl';

import type { Locale, UserRole } from '@/domain/enums';
import { CSRF_FIELD } from '@/lib/security/csrf-constants';
import { SelectField, TextField } from '@/components/fields';
import { SubmitButton } from '@/components/SubmitButton';
import { useToast } from '@/components/ui/toast';
import { resetToInitialCorpus, createUserAccount, updateUserAccount } from '@/server/actions/admin';
import { approveTranslation } from '@/server/actions/translation';
import { exportAllData } from '@/server/actions/data-export';
import type { FormActionState } from '@/server/actions/shared';

const initialState: FormActionState = {};

interface UserRow {
  id: number;
  email: string;
  displayName: string;
  role: UserRole;
  isActive: boolean;
  lastLoginAt: string | null;
  createdAt: string;
}

interface PendingTranslation {
  id: number;
  entityType: string;
  entityId: number;
  field: string;
  locale: Locale;
  value: string;
  origin: string;
}

interface AuditEntry {
  id: number;
  action: string;
  actorEmail: string;
  entityType: string;
  entityId: string;
  outcome: string;
  createdAt: string;
}

export function AdminClient({
  currentUserId,
  users,
  roles,
  pendingTranslations,
  auditEntries,
  lastSync,
  hasTencentCredentials,
  csrfToken,
}: {
  currentUserId: number;
  users: UserRow[];
  roles: readonly UserRole[];
  pendingTranslations: PendingTranslation[];
  auditEntries: AuditEntry[];
  lastSync: { status: string; finishedAt: string | null; sourceKind: string; error: string } | null;
  hasTencentCredentials: boolean;
  csrfToken: string;
}) {
  const t = useTranslations('admin');
  const tProducts = useTranslations('products');

  return (
    <div className="stack">
      <UsersSection currentUserId={currentUserId} users={users} roles={roles} csrfToken={csrfToken} />

      <div className="card">
        <h3>{t('sync')}</h3>
        <p className="small">
          {lastSync
            ? `${lastSync.status} - ${tProducts('syncLast', { when: lastSync.finishedAt ? new Date(lastSync.finishedAt).toLocaleString() : '-', source: lastSync.sourceKind })}`
            : tProducts('syncNever')}
          {!hasTencentCredentials ? ` - ${tProducts('syncUnavailable')}` : ''}
        </p>
        {lastSync?.error ? <p className="field-error">{lastSync.error}</p> : null}
      </div>

      {pendingTranslations.length > 0 ? <TranslationReviewSection items={pendingTranslations} csrfToken={csrfToken} /> : null}

      <DataSection csrfToken={csrfToken} />

      <AuditSection entries={auditEntries} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

function UsersSection({
  currentUserId,
  users,
  roles,
  csrfToken,
}: {
  currentUserId: number;
  users: UserRow[];
  roles: readonly UserRole[];
  csrfToken: string;
}) {
  const t = useTranslations('admin');
  const tCommon = useTranslations('common');
  const [createState, createAction] = useActionState(createUserAccount, initialState);
  const [showCreate, setShowCreate] = useState(false);
  // `useActionState` hands back a new object each time the action settles, so
  // comparing identity during render (rather than `success` in a `useEffect`)
  // reacts to exactly one settle without the extra render pass an effect costs.
  const [handledCreateState, setHandledCreateState] = useState(createState);
  if (createState !== handledCreateState) {
    setHandledCreateState(createState);
    if (createState.success) setShowCreate(false);
  }

  return (
    <div className="card">
      <div className="spread">
        <h3>{t('users')}</h3>
        <button type="button" className="primary" onClick={() => setShowCreate((v) => !v)}>
          {t('addUser')}
        </button>
      </div>

      {showCreate ? (
        <form action={createAction} className="form-grid" style={{ marginBottom: 16 }}>
          <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
          <TextField label={t('colEmail')} name="email" type="email" errors={createState.errors} required />
          <TextField label={t('colName')} name="displayName" />
          <SelectField label={t('colRole')} name="role" defaultValue="viewer" options={roles} />
          <div className="full row">
            <SubmitButton className="primary" pendingLabel={tCommon('saving')}>
              {tCommon('save')}
            </SubmitButton>
          </div>
          {createState.message ? <span className="field-error full">{createState.message}</span> : null}
        </form>
      ) : null}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{t('colEmail')}</th>
              <th>{t('colName')}</th>
              <th>{t('colRole')}</th>
              <th>{t('colStatus')}</th>
              <th>{t('colLastLogin')}</th>
              <th>{tCommon('actions')}</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <UserRowItem key={user.id} user={user} roles={roles} isSelf={user.id === currentUserId} csrfToken={csrfToken} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function UserRowItem({
  user,
  roles,
  isSelf,
  csrfToken,
}: {
  user: UserRow;
  roles: readonly UserRole[];
  isSelf: boolean;
  csrfToken: string;
}) {
  const t = useTranslations('admin');
  const tCommon = useTranslations('common');
  const [state, formAction] = useActionState(updateUserAccount, initialState);

  return (
    <tr>
      <td>{user.email}</td>
      <td>{user.displayName}</td>
      <td colSpan={2}>
        <form action={formAction} className="row">
          <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
          <input type="hidden" name="id" value={user.id} />
          <input type="hidden" name="displayName" value={user.displayName} />
          <select name="role" defaultValue={user.role} disabled={isSelf}>
            {roles.map((role) => (
              <option key={role} value={role}>
                {role}
              </option>
            ))}
          </select>
          <label className="row">
            <input type="checkbox" name="isActive" value="true" defaultChecked={user.isActive} disabled={isSelf} style={{ width: 'auto' }} />
            {t('active')}
          </label>
          <SubmitButton disabled={isSelf}>{tCommon('save')}</SubmitButton>
          {state.message ? <span className="field-error">{state.message}</span> : null}
        </form>
      </td>
      <td>{user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleString() : '-'}</td>
      <td />
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Translation review
// ---------------------------------------------------------------------------

function TranslationReviewSection({ items, csrfToken }: { items: PendingTranslation[]; csrfToken: string }) {
  const t = useTranslations('translation');
  return (
    <div className="card">
      <h3>{t('reviewQueue')}</h3>
      <div className="stack">
        {items.map((item) => (
          <TranslationReviewItem key={item.id} item={item} csrfToken={csrfToken} />
        ))}
      </div>
    </div>
  );
}

function TranslationReviewItem({ item, csrfToken }: { item: PendingTranslation; csrfToken: string }) {
  const t = useTranslations('translation');

  return (
    <form
      action={async (formData) => {
        await approveTranslation(formData);
      }}
      className="row"
      style={{ borderBottom: '1px solid var(--line)', paddingBottom: 8 }}
    >
      <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
      <input type="hidden" name="id" value={item.id} />
      <input type="hidden" name="value" value={item.value} />
      <div style={{ flex: 1 }}>
        <span className="small">
          {item.entityType} #{item.entityId} - {item.field} - {item.locale} - {item.origin}
        </span>
        <p style={{ margin: '4px 0' }}>{item.value}</p>
      </div>
      <button type="submit" name="status" value="approved" className="primary">
        {t('approve')}
      </button>
      <button type="submit" name="status" value="needs-review" className="danger">
        {t('reject')}
      </button>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Data export / reset
// ---------------------------------------------------------------------------

function DataSection({ csrfToken }: { csrfToken: string }) {
  const tCommon = useTranslations('common');
  const toast = useToast();
  const [exporting, setExporting] = useState(false);
  const [confirmingReset, setConfirmingReset] = useState(false);
  const [resetState, resetAction] = useActionState(resetToInitialCorpus, initialState);

  // Closing the confirm step is state derived from a new action result, so it
  // is set during render (see the `handledCreateState` comment above);
  // showing the toast is a genuine side effect on an external system (the
  // toast region) and stays in an effect.
  const [handledResetState, setHandledResetState] = useState(resetState);
  if (resetState !== handledResetState) {
    setHandledResetState(resetState);
    if (resetState.success) setConfirmingReset(false);
  }

  useEffect(() => {
    if (resetState.success) {
      toast.show(tCommon('saved'), 'success');
    } else if (resetState.message) {
      toast.show(resetState.message, 'error');
    }
    // toast.show is a stable callback from context; including it would refire
    // on every provider re-render for no reason.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resetState.success, resetState.message]);

  async function handleExport() {
    setExporting(true);
    try {
      const formData = new FormData();
      formData.set(CSRF_FIELD, csrfToken);
      const result = await exportAllData(formData);
      if (!result.ok || !result.data) {
        toast.show(result.message ?? 'Export failed.', 'error');
        return;
      }
      const blob = new Blob([JSON.stringify(result.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `bd-os-export-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.show(tCommon('saved'), 'success');
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="card">
      <div className="row">
        <button type="button" onClick={handleExport} disabled={exporting}>
          {exporting ? tCommon('loading') : tCommon('exportJson')}
        </button>
      </div>

      <form action={resetAction} className="row" style={{ marginTop: 12 }}>
        <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
        {confirmingReset ? (
          <>
            <input type="text" name="confirm" placeholder="RESET" style={{ width: 120 }} autoFocus />
            <SubmitButton className="danger">{tCommon('reset')}</SubmitButton>
            <button type="button" onClick={() => setConfirmingReset(false)}>
              {tCommon('cancel')}
            </button>
          </>
        ) : (
          <button type="button" className="danger" onClick={() => setConfirmingReset(true)}>
            {tCommon('reset')}
          </button>
        )}
        {resetState.errors?.confirm ? <span className="field-error">{resetState.errors.confirm[0]}</span> : null}
      </form>
      {confirmingReset ? <p className="small">{tCommon('resetConfirm')}</p> : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

function AuditSection({ entries }: { entries: AuditEntry[] }) {
  const t = useTranslations('admin');

  return (
    <div className="card">
      <h3>{t('audit')}</h3>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{t('auditWhen')}</th>
              <th>{t('auditAction')}</th>
              <th>{t('auditActor')}</th>
              <th>{t('auditEntity')}</th>
              <th>{t('auditOutcome')}</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <tr key={entry.id}>
                <td>{new Date(entry.createdAt).toLocaleString()}</td>
                <td>{entry.action}</td>
                <td>{entry.actorEmail || '-'}</td>
                <td>
                  {entry.entityType} {entry.entityId}
                </td>
                <td>
                  <span className="pill" data-tone={entry.outcome === 'failure' ? 'danger' : 'success'}>
                    {entry.outcome}
                  </span>
                </td>
              </tr>
            ))}
            {entries.length === 0 ? (
              <tr>
                <td colSpan={5} className="empty-state">
                  {t('auditEmpty')}
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}
