/**
 * The Weekly CEO Review question set.
 *
 * Code-owned and fixed, not stored in the database: the source application
 * kept these as a constant array, and `reviewAnswers` persists only the answer
 * keyed by index against this list. Message text lives in the i18n catalogs
 * under `weekly.q0`..`weekly.q24`; this file supplies the grouping and stable
 * indices those keys are keyed by.
 *
 * The index is the durable identifier: it is what `review_answers.question_index`
 * stores, so reordering entries here would silently reattach existing answers to
 * the wrong question. Append new questions at the end of their group's range
 * only.
 */

export interface ReviewGroup {
  readonly titleKey: `weekly.group${1 | 2 | 3 | 4 | 5 | 6}`;
  readonly questionKeys: readonly `weekly.q${number}`[];
}

export const REVIEW_GROUPS: readonly ReviewGroup[] = [
  { titleKey: 'weekly.group1', questionKeys: ['weekly.q0', 'weekly.q1', 'weekly.q2', 'weekly.q3'] },
  { titleKey: 'weekly.group2', questionKeys: ['weekly.q4', 'weekly.q5', 'weekly.q6', 'weekly.q7'] },
  { titleKey: 'weekly.group3', questionKeys: ['weekly.q8', 'weekly.q9', 'weekly.q10', 'weekly.q11'] },
  { titleKey: 'weekly.group4', questionKeys: ['weekly.q12', 'weekly.q13', 'weekly.q14', 'weekly.q15'] },
  { titleKey: 'weekly.group5', questionKeys: ['weekly.q16', 'weekly.q17', 'weekly.q18', 'weekly.q19'] },
  { titleKey: 'weekly.group6', questionKeys: ['weekly.q20', 'weekly.q21', 'weekly.q22', 'weekly.q23', 'weekly.q24'] },
];

/** Flat, index-addressable view: `REVIEW_QUESTIONS[i]` is question `weekly.q{i}`. */
export const REVIEW_QUESTIONS: readonly string[] = REVIEW_GROUPS.flatMap((g) => g.questionKeys);

export const REVIEW_QUESTION_COUNT = REVIEW_QUESTIONS.length;
