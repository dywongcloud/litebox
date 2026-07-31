'use client';

import { useActionState, useState } from 'react';
import { useTranslations } from 'next-intl';

import { CSRF_FIELD } from '@/lib/security/csrf-constants';
import { SubmitButton } from '@/components/SubmitButton';
import { saveReviewAnswer } from '@/server/actions/review';
import type { FormActionState } from '@/server/actions/shared';

const initialState: FormActionState = {};

interface QuestionData {
  index: number;
  text: string;
  answer: string;
}

export function WeeklyClient({
  groups,
  answeredCount,
  totalCount,
  canWrite,
  csrfToken,
}: {
  groups: { title: string; questions: QuestionData[] }[];
  answeredCount: number;
  totalCount: number;
  canWrite: boolean;
  csrfToken: string;
}) {
  const t = useTranslations('weekly');

  return (
    <div className="stack">
      <div className="spread">
        <h2 style={{ margin: 0 }}>{t('heading')}</h2>
        <span className="pill" data-tone="brand">
          {t('answered', { count: answeredCount, total: totalCount })}
        </span>
      </div>

      <div className="grid-3">
        {groups.map((group) => (
          <div className="card" key={group.title}>
            <h3>{group.title}</h3>
            <div className="stack">
              {group.questions.map((question) => (
                <ReviewQuestion key={question.index} question={question} canWrite={canWrite} csrfToken={csrfToken} />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ReviewQuestion({ question, canWrite, csrfToken }: { question: QuestionData; canWrite: boolean; csrfToken: string }) {
  const t = useTranslations('weekly');
  const [state, formAction] = useActionState(saveReviewAnswer, initialState);
  const [expanded, setExpanded] = useState(false);
  // See the equivalent comment in AdminClient: collapsing on a new successful
  // save is state derived from the action result, set during render instead
  // of via an effect.
  const [handledState, setHandledState] = useState(state);
  if (state !== handledState) {
    setHandledState(state);
    if (state.success) setExpanded(false);
  }

  return (
    <div>
      <button
        type="button"
        className="review-question"
        data-done={question.answer.trim() !== ''}
        onClick={() => setExpanded((e) => !e)}
        style={{ width: '100%', textAlign: 'left' }}
      >
        {question.text}
      </button>

      {expanded ? (
        <form action={formAction} className="stack" style={{ marginTop: 6 }}>
          <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
          <input type="hidden" name="questionIndex" value={question.index} />
          <textarea name="answer" defaultValue={question.answer} placeholder={t('answerPlaceholder')} readOnly={!canWrite} />
          {state.message ? <span className="field-error">{state.message}</span> : null}
          {canWrite ? <SubmitButton className="primary">{t('saveAndClose')}</SubmitButton> : null}
        </form>
      ) : null}
    </div>
  );
}
