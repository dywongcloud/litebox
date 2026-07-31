'use server';

import { revalidatePath } from 'next/cache';

import { formDataToObject, translationRequestSchema, translationReviewSchema } from '@/domain/schemas';
import * as audit from '@/lib/security/audit';
import { requireMutation } from '@/lib/auth/guard';
import { reviewTranslation } from '@/server/data/translations';
import { translateField } from '@/server/translation/service';

import { describeGuardError, type FormActionState } from './shared';

const ENTITY_PATH: Record<string, string> = {
  product: '/[locale]/products',
  account: '/[locale]/accounts',
  motion: '/[locale]/playbooks',
  todo: '/[locale]/board',
};

export interface TranslateState extends FormActionState {
  readonly value?: string;
  readonly stale?: boolean;
}

export async function requestTranslation(_prev: TranslateState, formData: FormData): Promise<TranslateState> {
  let actor;
  try {
    actor = await requireMutation('translation.request', formData, { bucket: 'translate' });
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const parsed = translationRequestSchema.safeParse(formDataToObject(formData));
  if (!parsed.success) return { message: 'Invalid translation request.' };

  const { entityType, entityId, field, sourceLocale, targetLocale } = parsed.data;

  if (sourceLocale === targetLocale) {
    return { message: 'Source and target language must differ.' };
  }

  const result = await translateField(entityType, entityId, field, sourceLocale, targetLocale);

  if (!result.ok) {
    const messages: Record<typeof result.reason, string> = {
      unavailable: 'Machine translation is not configured. Simplified and Traditional conversion is still available.',
      'too-long': `Text is too long to translate in one request (${result.detail ?? ''} characters).`,
      'invalid-field': 'This field cannot be translated.',
      'not-found': 'That record no longer exists.',
      'upstream-error': `Translation failed: ${result.detail ?? 'unknown error'}`,
    };
    return { message: messages[result.reason] };
  }

  audit.record({
    action: 'translation.requested',
    actorUserId: actor.user.id,
    entityType,
    entityId,
    metadata: { field, sourceLocale, targetLocale, origin: result.translation.origin },
  });

  revalidatePath(ENTITY_PATH[entityType] ?? '/[locale]/products', 'page');

  return { success: true, value: result.translation.value };
}

export async function approveTranslation(formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('translation.approve', formData);
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const parsed = translationReviewSchema.safeParse(formDataToObject(formData));
  if (!parsed.success) return { message: 'Invalid request.' };

  const updated = reviewTranslation(parsed.data.id, parsed.data.status, actor.user.id, parsed.data.value);
  if (!updated) return { message: 'That translation no longer exists.' };

  audit.record({
    action: parsed.data.status === 'approved' ? 'translation.approved' : 'translation.rejected',
    actorUserId: actor.user.id,
    entityType: updated.entityType,
    entityId: updated.entityId,
    metadata: { field: updated.field, locale: updated.locale },
  });

  revalidatePath('/[locale]/admin', 'page');
  return { success: true };
}
