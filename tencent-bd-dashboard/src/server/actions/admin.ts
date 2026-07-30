'use server';

import { revalidatePath } from 'next/cache';

import { formDataToObject, userCreateSchema, userUpdateSchema, toFieldErrors } from '@/domain/schemas';
import { passwordSchema } from '@/lib/auth/password-policy';
import * as session from '@/lib/auth/session';
import * as audit from '@/lib/security/audit';
import { requireMutation } from '@/lib/auth/guard';
import { hashPassword, randomToken } from '@/lib/security/crypto';
import { createUser, findByEmail, getUser, updateUser } from '@/server/data/users';
import { applySeedCorpus } from '@/db/seed-corpus';

import { describeGuardError, type FormActionState } from './shared';

/**
 * A newly created user has no password of their own yet: they are given a
 * random, never-displayed placeholder hash and must reach their account
 * through a password reset flow before signing in.
 *
 * This app does not yet send email, so in practice an administrator using
 * this action must separately run `db:seed`-style provisioning or a future
 * "send reset link" feature to activate the account. This is stated
 * explicitly here rather than silently minting a guessable temporary
 * password, which would be the less safe shortcut.
 */
export async function createUserAccount(_prev: FormActionState, formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('user.manage', formData);
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const parsed = userCreateSchema.safeParse(formDataToObject(formData));
  if (!parsed.success) return { errors: toFieldErrors(parsed.error) };

  const existing = findByEmail(parsed.data.email);
  if (existing) return { errors: { email: ['A user with this email already exists.'] } };

  // Unguessable placeholder: a random 32-byte value is hashed and discarded
  // immediately, so no one -- including this process -- ever holds a usable
  // password for the new account.
  const placeholder = await hashPassword(randomToken(32));

  const created = createUser({
    email: parsed.data.email,
    displayName: parsed.data.displayName,
    role: parsed.data.role,
    passwordHash: placeholder,
    isActive: true,
  });

  audit.record({ action: 'user.created', actorUserId: actor.user.id, entityType: 'user', entityId: created.id });

  revalidatePath('/[locale]/admin', 'page');
  return { success: true };
}

export async function updateUserAccount(_prev: FormActionState, formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('user.manage', formData);
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const parsed = userUpdateSchema.safeParse(formDataToObject(formData));
  if (!parsed.success) return { errors: toFieldErrors(parsed.error) };

  const target = getUser(parsed.data.id);
  if (!target) return { message: 'That user no longer exists.' };

  if (target.id === actor.user.id && !parsed.data.isActive) {
    return { message: 'You cannot deactivate your own account.' };
  }
  if (target.id === actor.user.id && parsed.data.role !== 'admin') {
    return { message: 'You cannot remove your own administrator role.' };
  }

  updateUser(parsed.data.id, {
    displayName: parsed.data.displayName,
    role: parsed.data.role,
    isActive: parsed.data.isActive,
  });

  if (!parsed.data.isActive) {
    session.revokeAllForUser(parsed.data.id);
  }

  audit.record({
    action: parsed.data.isActive ? 'user.updated' : 'user.deactivated',
    actorUserId: actor.user.id,
    entityType: 'user',
    entityId: parsed.data.id,
    metadata: { role: parsed.data.role },
  });

  revalidatePath('/[locale]/admin', 'page');
  return { success: true };
}

/**
 * Restore the bundled initial corpus.
 *
 * Requires the literal confirmation phrase in `confirm`, checked after all
 * other guards: a destructive, irreversible action should not be reachable by
 * a single misclick, and a translated or mistyped confirmation must fail
 * rather than silently proceed.
 */
export async function resetToInitialCorpus(_prev: FormActionState, formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('data.reset', formData);
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const confirmation = String(formData.get('confirm') ?? '');
  if (confirmation !== 'RESET') {
    return { errors: { confirm: ['Type RESET in capital letters to confirm.'] } };
  }

  applySeedCorpus();
  audit.record({ action: 'data.reset', actorUserId: actor.user.id });

  revalidatePath('/', 'layout');
  return { success: true };
}
