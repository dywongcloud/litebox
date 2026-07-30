import { getTranslations } from 'next-intl/server';

import { can } from '@/lib/auth/rbac';
import * as session from '@/lib/auth/session';
import { readToken } from '@/lib/security/csrf';
import { REVIEW_GROUPS } from '@/domain/review-questions';
import { getAnswers } from '@/server/data/review';

import { WeeklyClient } from './WeeklyClient';

export default async function WeeklyPage() {
  const active = await session.current();
  if (!active) return null;

  const t = await getTranslations();
  const answers = getAnswers(active.user.id);
  const canWrite = can(active.user.role, 'review.write');
  const csrfToken = await readToken(active.sessionId);

  let index = 0;
  const groups = REVIEW_GROUPS.map((group) => ({
    title: t(group.titleKey),
    questions: group.questionKeys.map((key) => {
      const questionIndex = index++;
      return { index: questionIndex, text: t(key as 'weekly.q0'), answer: answers.get(questionIndex) ?? '' };
    }),
  }));

  const answeredCount = [...answers.values()].filter((v) => v.trim() !== '').length;

  return <WeeklyClient groups={groups} answeredCount={answeredCount} totalCount={index} canWrite={canWrite} csrfToken={csrfToken} />;
}
