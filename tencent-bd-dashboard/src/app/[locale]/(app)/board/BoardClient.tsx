'use client';

import { useActionState, useEffect, useMemo, useState } from 'react';
import { useTranslations } from 'next-intl';
import {
  DndContext,
  DragOverlay,
  KeyboardSensor,
  PointerSensor,
  closestCorners,
  useDroppable,
  useSensor,
  useSensors,
} from '@dnd-kit/core';
import type { DragEndEvent, DragOverEvent, DragStartEvent } from '@dnd-kit/core';
import { SortableContext, sortableKeyboardCoordinates, useSortable, verticalListSortingStrategy } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';

import { TODO_OWNERS, TODO_PRIORITIES, TODO_STATUSES } from '@/domain/enums';
import type { TodoStatus } from '@/domain/enums';
import type { Todo } from '@/db/schema';
import { CSRF_FIELD } from '@/lib/security/csrf-constants';
import { ConfirmButton } from '@/components/ConfirmButton';
import { Modal } from '@/components/Modal';
import { SelectField, TextAreaField, TextField } from '@/components/fields';
import { SubmitButton } from '@/components/SubmitButton';
import { useToast } from '@/components/Toast';
import { moveTodoCard, removeTodo, saveTodo } from '@/server/actions/board';
import type { FormActionState } from '@/server/actions/shared';

const initialState: FormActionState = {};

const COLUMN_LABELS: Record<TodoStatus, string> = {
  Backlog: 'colBacklog',
  'This Week': 'colWeek',
  'In Progress': 'colProgress',
  Done: 'colDone',
};

type ColumnState = Record<TodoStatus, number[]>;

function groupByStatus(items: Todo[]): ColumnState {
  const grouped = Object.fromEntries(TODO_STATUSES.map((status) => [status, [] as number[]])) as ColumnState;
  for (const todo of items) grouped[todo.status].push(todo.id);
  return grouped;
}

function containerOf(columns: ColumnState, id: number): TodoStatus | undefined {
  return TODO_STATUSES.find((status) => columns[status].includes(id));
}

export function BoardClient({ items, canWrite, csrfToken }: { items: Todo[]; canWrite: boolean; csrfToken: string }) {
  const t = useTranslations('board');
  const tCommon = useTranslations('common');
  const toast = useToast();
  const [modal, setModal] = useState<{ type: 'create' } | { type: 'edit'; todo: Todo } | null>(null);

  const todosById = useMemo(() => new Map(items.map((todo) => [todo.id, todo])), [items]);
  const [columns, setColumns] = useState<ColumnState>(() => groupByStatus(items));
  const [activeId, setActiveId] = useState<number | null>(null);

  // The server is the source of truth: whenever a fresh `items` prop arrives
  // (after a save, delete, or `revalidatePath` following a move), resync the
  // local drag order to it during render -- this is the "adjusting state
  // when a prop changes" case, not a side effect on an external system, so it
  // does not belong in a `useEffect`. A drag in flight keeps its own
  // optimistic order via onDragOver until onDragEnd persists and the next
  // `items` prop takes back over here.
  const [syncedItems, setSyncedItems] = useState(items);
  if (items !== syncedItems) {
    setSyncedItems(items);
    setColumns(groupByStatus(items));
  }

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  function handleDragStart(event: DragStartEvent) {
    setActiveId(Number(event.active.id));
  }

  function handleDragOver(event: DragOverEvent) {
    const { active, over } = event;
    if (!over) return;

    const activeId = Number(active.id);
    const overId = String(over.id);

    const from = containerOf(columns, activeId);
    const to = (TODO_STATUSES as readonly string[]).includes(overId)
      ? (overId as TodoStatus)
      : containerOf(columns, Number(overId));
    if (!from || !to || from === to) return;

    setColumns((current) => {
      const sourceIds = current[from].filter((id) => id !== activeId);
      const overIndex = current[to].indexOf(Number(overId));
      const insertAt = overIndex >= 0 ? overIndex : current[to].length;
      const destIds = [...current[to]];
      destIds.splice(insertAt, 0, activeId);
      return { ...current, [from]: sourceIds, [to]: destIds };
    });
  }

  async function handleDragEnd(event: DragEndEvent) {
    setActiveId(null);
    const { active, over } = event;
    if (!over || !canWrite) return;

    const id = Number(active.id);
    const overId = String(over.id);
    const status =
      (TODO_STATUSES as readonly string[]).includes(overId) ? (overId as TodoStatus) : containerOf(columns, Number(overId));
    if (!status) return;

    const ids = columns[status];
    const position = ids.includes(id) ? ids.indexOf(id) : ids.length;

    const formData = new FormData();
    formData.set(CSRF_FIELD, csrfToken);
    formData.set('id', String(id));
    formData.set('status', status);
    formData.set('position', String(position));

    const result = await moveTodoCard(formData);
    if (!result.success) {
      toast.show(result.message ?? 'Could not move that card.', 'error');
      setColumns(groupByStatus(items));
    }
  }

  const activeTodo = activeId !== null ? todosById.get(activeId) : undefined;

  return (
    <>
      {canWrite ? (
        <div style={{ marginBottom: 10 }}>
          <button type="button" className="primary" onClick={() => setModal({ type: 'create' })}>
            {t('addTodo')}
          </button>
        </div>
      ) : null}

      <DndContext
        sensors={sensors}
        collisionDetection={closestCorners}
        onDragStart={handleDragStart}
        onDragOver={handleDragOver}
        onDragEnd={handleDragEnd}
        onDragCancel={() => setActiveId(null)}
      >
        <div className="board">
          {TODO_STATUSES.map((status) => (
            <BoardColumn key={status} status={status} label={t(COLUMN_LABELS[status] as 'colBacklog')}>
              <SortableContext items={columns[status]} strategy={verticalListSortingStrategy}>
                {columns[status].map((id) => {
                  const todo = todosById.get(id);
                  if (!todo) return null;
                  return (
                    <TodoCard
                      key={todo.id}
                      todo={todo}
                      canWrite={canWrite}
                      csrfToken={csrfToken}
                      onEdit={() => setModal({ type: 'edit', todo })}
                    />
                  );
                })}
              </SortableContext>
              {columns[status].length === 0 ? <p className="small">{tCommon('emptyState')}</p> : null}
            </BoardColumn>
          ))}
        </div>

        <DragOverlay>
          {activeTodo ? <TodoCard todo={activeTodo} canWrite={canWrite} csrfToken={csrfToken} onEdit={() => {}} overlay /> : null}
        </DragOverlay>
      </DndContext>

      {modal ? <TodoFormModal todo={modal.type === 'edit' ? modal.todo : undefined} csrfToken={csrfToken} onClose={() => setModal(null)} /> : null}
    </>
  );
}

function BoardColumn({ status, label, children }: { status: TodoStatus; label: string; children: React.ReactNode }) {
  const { setNodeRef, isOver } = useDroppable({ id: status });
  return (
    <div className="board-col" ref={setNodeRef} data-drop-active={isOver}>
      <h3>{label}</h3>
      {children}
    </div>
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
  overlay = false,
}: {
  todo: Todo;
  canWrite: boolean;
  csrfToken: string;
  onEdit: () => void;
  overlay?: boolean;
}) {
  const t = useTranslations('board');
  const tCommon = useTranslations('common');
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id: todo.id,
    disabled: !canWrite || overlay,
  });

  const style = overlay
    ? undefined
    : {
        transform: CSS.Transform.toString(transform),
        transition,
      };

  return (
    <div
      className="todo-card"
      data-done={todo.status === 'Done'}
      data-dragging={isDragging}
      ref={overlay ? undefined : setNodeRef}
      style={style}
    >
      <div className="todo-card-head">
        <div className="todo-title">{todo.title}</div>
        {canWrite ? (
          <button
            type="button"
            className="todo-drag-handle"
            aria-label={t('dragHandle')}
            {...attributes}
            {...listeners}
          >
            ⠿
          </button>
        ) : null}
      </div>
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
          >
            <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
            <input type="hidden" name="id" value={todo.id} />
            <ConfirmButton label={tCommon('delete')} />
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
      {/* Appends to the end of the target column; this is the keyboard- and
          screen-reader-accessible alternative to the drag handle above, which
          reorders within a column too but only via pointer or arrow keys. */}
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
