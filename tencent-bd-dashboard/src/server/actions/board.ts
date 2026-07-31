'use server';

import { revalidatePath } from 'next/cache';

import {
  formDataToObject,
  idSchema,
  motionSchema,
  sopChecklistSchema,
  todoMoveSchema,
  todoSchema,
  toFieldErrors,
} from '@/domain/schemas';
import * as audit from '@/lib/security/audit';
import { requireMutation } from '@/lib/auth/guard';
import {
  createMotion,
  createTodo,
  deleteMotion,
  deleteTodo,
  getMotion,
  getTodo,
  moveTodo,
  replaceSopSteps,
  updateMotion,
  updateTodo,
} from '@/server/data/board';

import { describeGuardError, type FormActionState } from './shared';

// ---------------------------------------------------------------------------
// Next-Step Board (todos)
// ---------------------------------------------------------------------------

export async function saveTodo(_prev: FormActionState, formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('board.write', formData);
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const parsed = todoSchema.safeParse(formDataToObject(formData));
  if (!parsed.success) return { errors: toFieldErrors(parsed.error) };

  const id = idSchema.safeParse(formData.get('id'));

  if (id.success) {
    const existing = getTodo(id.data);
    if (!existing) return { message: 'That item no longer exists.' };
    updateTodo(id.data, parsed.data);
    audit.record({ action: 'todo.updated', actorUserId: actor.user.id, entityType: 'todo', entityId: id.data });
  } else {
    const created = createTodo(parsed.data);
    audit.record({ action: 'todo.created', actorUserId: actor.user.id, entityType: 'todo', entityId: created.id });
  }

  revalidatePath('/[locale]/board', 'page');
  return { success: true };
}

export async function removeTodo(formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('board.write', formData);
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const id = idSchema.safeParse(formData.get('id'));
  if (!id.success) return { message: 'Invalid item.' };

  const deleted = deleteTodo(id.data);
  if (deleted) {
    audit.record({ action: 'todo.deleted', actorUserId: actor.user.id, entityType: 'todo', entityId: id.data });
  }

  revalidatePath('/[locale]/board', 'page');
  return { success: deleted };
}

export async function moveTodoCard(formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('board.write', formData);
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const parsed = todoMoveSchema.safeParse(formDataToObject(formData));
  if (!parsed.success) return { errors: toFieldErrors(parsed.error) };

  const moved = moveTodo(parsed.data.id, parsed.data.status, parsed.data.position);
  if (moved) {
    audit.record({
      action: 'todo.updated',
      actorUserId: actor.user.id,
      entityType: 'todo',
      entityId: parsed.data.id,
      metadata: { status: parsed.data.status, position: parsed.data.position },
    });
  }

  revalidatePath('/[locale]/board', 'page');
  return { success: Boolean(moved) };
}

// ---------------------------------------------------------------------------
// Development SOP checklist
// ---------------------------------------------------------------------------

export async function saveSopChecklist(_prev: FormActionState, formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('playbook.write', formData);
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const steps = formData.getAll('steps').map(String);
  const parsed = sopChecklistSchema.safeParse({ steps });
  if (!parsed.success) return { errors: toFieldErrors(parsed.error) };

  // Blank rows are how the UI represents a deleted step; drop them on save
  // rather than persisting an empty checklist entry.
  replaceSopSteps(parsed.data.steps.filter((s) => s.trim() !== ''));
  audit.record({ action: 'sop.saved', actorUserId: actor.user.id, metadata: { count: parsed.data.steps.length } });

  revalidatePath('/[locale]/sop', 'page');
  return { success: true };
}

// ---------------------------------------------------------------------------
// Sales motion playbooks
// ---------------------------------------------------------------------------

export async function saveMotion(_prev: FormActionState, formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('playbook.write', formData);
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const parsed = motionSchema.safeParse(formDataToObject(formData));
  if (!parsed.success) return { errors: toFieldErrors(parsed.error) };

  const id = idSchema.safeParse(formData.get('id'));

  if (id.success) {
    const existing = getMotion(id.data);
    if (!existing) return { message: 'That motion no longer exists.' };
    updateMotion(id.data, parsed.data);
    audit.record({ action: 'motion.updated', actorUserId: actor.user.id, entityType: 'motion', entityId: id.data });
  } else {
    const created = createMotion(parsed.data);
    audit.record({ action: 'motion.created', actorUserId: actor.user.id, entityType: 'motion', entityId: created.id });
  }

  revalidatePath('/[locale]/playbooks', 'page');
  return { success: true };
}

export async function removeMotion(formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('playbook.write', formData);
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const id = idSchema.safeParse(formData.get('id'));
  if (!id.success) return { message: 'Invalid motion.' };

  const deleted = deleteMotion(id.data);
  if (deleted) {
    audit.record({ action: 'motion.deleted', actorUserId: actor.user.id, entityType: 'motion', entityId: id.data });
  }

  revalidatePath('/[locale]/playbooks', 'page');
  return { success: deleted };
}
