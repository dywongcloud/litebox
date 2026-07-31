'use client';

import { useActionState, useEffect, useState } from 'react';
import { useTranslations } from 'next-intl';

import { TODO_OWNERS, TODO_PRIORITIES, TODO_STATUSES } from '@/domain/enums';
import type { TodoStatus } from '@/domain/enums';
import type { Todo } from '@/db/schema';
import { CSRF_FIELD } from '@/lib/security/csrf-constants';
import { Modal } from '@/components/Modal';
import { SelectField, TextAreaField, TextField } from '@/components/fields';
import { SubmitButton } from '@/components/SubmitButton';
import { moveTodoCard, removeTodo, saveTodo } from '@/server/actions/board';
import type { FormActionState } from '@/server/actions/shared';

const initialState: FormActionState = {};

const COLUMN_LABELS: Record<TodoStatus, string> = {
  Backlog: 'colBacklog',
  'This Week': 'colWeek',
  'In Progress': 'colProgress',
  Done: 'colDone',
};

export function BoardClient({ items, canWrite, csrfToken }: { items: Todo[]; canWrite: boolean; csrfToken: string }) {
  const t = useTranslations('board');
  const tCommon = useTranslations('common');
  const [modal, setModal] = useState<{ type: 'create' } | { type: 'edit'; todo: Todo } | null>(null);

  const byStatus = Object.fromEntries(TODO_STATUSES.map((status) => [status, items.filter((i) => i.status === status)])) as Record<
    TodoStatus,
    Todo[]
  >;

  return (
    <>
      {canWrite ? (
        <div style={{ marginBottom: 10 }}>
          <button type="button" className="primary" onClick={() => setModal({ type: 'create' })}>
            {t('addTodo')}
          </button>
        </div>
      ) : null}

      <div className="board">
        {TODO_STATUSES.map((status) => (
          <div className="board-col" key={status}>
            <h3>{t(COLUMN_LABELS[status] as 'colBacklog')}</h3>
            {byStatus[status].map((todo) => (
              <TodoCard
                key={todo.id}
                todo={todo}
                canWrite={canWrite}
                csrfToken={csrfToken}
                onEdit={() => setModal({ type: 'edit', todo })}
              />
            ))}
            {byStatus[status].length === 0 ? <p className="small">{tCommon('emptyState')}</p> : null}
          </div>
        ))}
      </div>

      {modal ? <TodoFormModal todo={modal.type === 'edit' ? modal.todo : undefined} csrfToken={csrfToken} onClose={() => setModal(null)} /> : null}
    </>
  );
}

function isOverdue(dueOn: string): boolean {
  if (!dueOn) return false;
  return dueOn < new Date().toISOString().slice(0, 10);
}

function TodoCard({
  todo,
  canWrite,
  csrfToken,
  onEdit,
}: {
  todo: Todo;
  canWrite: boolean;
  csrfToken: string;
  onEdit: () => void;
}) {
  const t = useTranslations('board');
  const tCommon = useTranslations('common');

  return (
    <div className="todo-card" data-done={todo.status === 'Done'}>
      <div className="todo-title">{todo.title}</div>
      <div className="meta">
        <span className="pill" data-tone="neutral">
          {todo.owner}
        </span>
        <span className="pill" data-tone={todo.priority === 'P0' ? 'danger' : 'brand'}>
          {todo.priority}
        </span>
        {todo.dueOn ? (
          <span className="pill" data-tone={isOverdue(todo.dueOn) ? 'danger' : 'neutral'}>
            {todo.dueOn} {isOverdue(todo.dueOn) ? `(${t('overdue')})` : ''}
          </span>
        ) : null}
      </div>
      {todo.detail ? <p className="small">{todo.detail}</p> : null}
      {todo.link ? (
        <p className="small">
          <a href={todo.link} target="_blank" rel="noreferrer noopener">
            {todo.link}
          </a>
        </p>
      ) : null}

      {canWrite ? (
        <div className="row" style={{ marginTop: 8 }}>
          <button type="button" onClick={onEdit}>
            {tCommon('edit')}
          </button>
          <MoveSelect todo={todo} csrfToken={csrfToken} />
          <form
            action={async (formData) => {
              await removeTodo(formData);
            }}
            onSubmit={(event) => {
              if (!window.confirm(tCommon('confirmDelete'))) event.preventDefault();
            }}
          >
            <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
            <input type="hidden" name="id" value={todo.id} />
            <button type="submit" className="danger">
              {tCommon('delete')}
            </button>
          </form>
        </div>
      ) : null}
    </div>
  );
}

function MoveSelect({ todo, csrfToken }: { todo: Todo; csrfToken: string }) {
  return (
    <form
      action={async (formData) => {
        await moveTodoCard(formData);
      }}
    >
      <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
      <input type="hidden" name="id" value={todo.id} />
      {/* Appends to the end of the target column; within-column reordering is
          not exposed in this UI -- `position` still exists for a future drag
          interaction to use without a data model change. */}
      <input type="hidden" name="position" value={9999} />
      <select
        name="status"
        defaultValue={todo.status}
        onChange={(event) => event.currentTarget.form?.requestSubmit()}
        aria-label="Move to"
      >
        {TODO_STATUSES.map((status) => (
          <option key={status} value={status}>
            {status}
          </option>
        ))}
      </select>
    </form>
  );
}

function TodoFormModal({ todo, csrfToken, onClose }: { todo?: Todo; csrfToken: string; onClose: () => void }) {
  const t = useTranslations('board');
  const tCommon = useTranslations('common');
  const [state, formAction] = useActionState(saveTodo, initialState);

  useEffect(() => {
    if (state.success) onClose();
  }, [state.success, onClose]);

  return (
    <Modal title={todo ? t('editTitle') : t('createTitle')} onClose={onClose}>
      <div className="modal-header">
        <h2 style={{ margin: 0 }}>{todo ? t('editTitle') : t('createTitle')}</h2>
        <button type="button" onClick={onClose}>
          {tCommon('close')}
        </button>
      </div>

      {state.message ? (
        <p className="form-message" data-tone="error" role="alert">
          {state.message}
        </p>
      ) : null}

      <form action={formAction} id="todo-form">
        <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
        {todo ? <input type="hidden" name="id" value={todo.id} /> : null}

        <div className="form-grid">
          <TextField className="full" label={t('fieldTitle')} name="title" defaultValue={todo?.title} errors={state.errors} required />
          <SelectField label={t('fieldOwner')} name="owner" defaultValue={todo?.owner ?? 'Me'} options={TODO_OWNERS} />
          <SelectField label={t('fieldPriority')} name="priority" defaultValue={todo?.priority ?? 'P2'} options={TODO_PRIORITIES} />
          <SelectField label={t('fieldStatus')} name="status" defaultValue={todo?.status ?? 'Backlog'} options={TODO_STATUSES} />
          <TextField label={t('fieldDue')} name="dueOn" type="date" defaultValue={todo?.dueOn} />
          <TextField label={t('fieldLink')} name="link" type="url" defaultValue={todo?.link} errors={state.errors} maxLength={2048} />
          <TextAreaField className="full" label={t('fieldDetail')} name="detail" defaultValue={todo?.detail} />
        </div>
      </form>

      <div className="modal-footer">
        <button type="button" onClick={onClose}>
          {tCommon('cancel')}
        </button>
        <SubmitButton form="todo-form" className="primary" pendingLabel={tCommon('saving')}>
          {tCommon('save')}
        </SubmitButton>
      </div>
    </Modal>
  );
}
