'use server';

import { revalidatePath } from 'next/cache';

import {
  accountResearchSchema,
  accountSchema,
  formDataToObject,
  idSchema,
  toFieldErrors,
} from '@/domain/schemas';
import * as audit from '@/lib/security/audit';
import { requireMutation } from '@/lib/auth/guard';
import {
  createAccount,
  deleteAccount,
  getAccount,
  saveAccountResearch,
  updateAccount,
} from '@/server/data/accounts';

import { describeGuardError, type FormActionState } from './shared';

export async function saveAccount(_prev: FormActionState, formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('account.write', formData);
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const parsed = accountSchema.safeParse(formDataToObject(formData));
  if (!parsed.success) return { errors: toFieldErrors(parsed.error) };

  const id = idSchema.safeParse(formData.get('id'));

  if (id.success) {
    const existing = getAccount(id.data);
    if (!existing) return { message: 'That account no longer exists.' };
    updateAccount(id.data, parsed.data);
    audit.record({ action: 'account.updated', actorUserId: actor.user.id, entityType: 'account', entityId: id.data });
  } else {
    const created = createAccount(parsed.data);
    audit.record({ action: 'account.created', actorUserId: actor.user.id, entityType: 'account', entityId: created.id });
  }

  revalidatePath('/[locale]/accounts', 'page');
  return { success: true };
}

export async function removeAccount(formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('account.delete', formData);
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const id = idSchema.safeParse(formData.get('id'));
  if (!id.success) return { message: 'Invalid account.' };

  const deleted = deleteAccount(id.data);
  if (deleted) {
    audit.record({ action: 'account.deleted', actorUserId: actor.user.id, entityType: 'account', entityId: id.data });
  }

  revalidatePath('/[locale]/accounts', 'page');
  return { success: deleted };
}

export async function saveResearch(_prev: FormActionState, formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('account.write', formData);
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const id = idSchema.safeParse(formData.get('accountId'));
  if (!id.success) return { message: 'Invalid account.' };

  const existing = getAccount(id.data);
  if (!existing) return { message: 'That account no longer exists.' };

  const parsed = accountResearchSchema.safeParse(formDataToObject(formData));
  if (!parsed.success) return { errors: toFieldErrors(parsed.error) };

  saveAccountResearch(id.data, parsed.data);
  audit.record({
    action: 'account.research.saved',
    actorUserId: actor.user.id,
    entityType: 'account',
    entityId: id.data,
  });

  revalidatePath('/[locale]/accounts', 'page');
  revalidatePath('/[locale]/accounts/[id]', 'page');
  return { success: true };
}
