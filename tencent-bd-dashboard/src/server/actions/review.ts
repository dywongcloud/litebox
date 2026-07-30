'use server';

import { revalidatePath } from 'next/cache';

import { formDataToObject, reviewAnswerSchema, toFieldErrors } from '@/domain/schemas';
import * as audit from '@/lib/security/audit';
import { requireMutation } from '@/lib/auth/guard';
import { saveAnswer } from '@/server/data/review';

import { describeGuardError, type FormActionState } from './shared';

export async function saveReviewAnswer(_prev: FormActionState, formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('review.write', formData);
  } catch (error) {
    return { message: describeGuardError(error) };
  }

  const parsed = reviewAnswerSchema.safeParse(formDataToObject(formData));
  if (!parsed.success) return { errors: toFieldErrors(parsed.error) };

  saveAnswer(actor.user.id, parsed.data.questionIndex, parsed.data.answer);
  audit.record({
    action: 'review.answered',
    actorUserId: actor.user.id,
    entityType: 'review-question',
    entityId: parsed.data.questionIndex,
  });

  revalidatePath('/[locale]/weekly', 'page');
  return { success: true };
}
