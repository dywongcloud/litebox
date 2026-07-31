import 'server-only';

import { and, eq } from 'drizzle-orm';

import { db } from '@/db/client';
import { reviewAnswers } from '@/db/schema';
import { REVIEW_QUESTION_COUNT } from '@/domain/review-questions';

/** Per-user answers to the fixed Weekly CEO Review question list. */
export function getAnswers(userId: number): Map<number, string> {
  const rows = db.select().from(reviewAnswers).where(eq(reviewAnswers.userId, userId)).all();
  return new Map(rows.map((r) => [r.questionIndex, r.answer]));
}

export function saveAnswer(userId: number, questionIndex: number, answer: string): void {
  if (questionIndex < 0 || questionIndex >= REVIEW_QUESTION_COUNT) {
    throw new RangeError(`questionIndex ${questionIndex} is out of range`);
  }

  const existing = db
    .select()
    .from(reviewAnswers)
    .where(and(eq(reviewAnswers.userId, userId), eq(reviewAnswers.questionIndex, questionIndex)))
    .get();

  if (existing) {
    db.update(reviewAnswers)
      .set({ answer, updatedAt: new Date() })
      .where(and(eq(reviewAnswers.userId, userId), eq(reviewAnswers.questionIndex, questionIndex)))
      .run();
  } else {
    db.insert(reviewAnswers).values({ userId, questionIndex, answer }).run();
  }
}
