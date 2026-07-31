import { getTranslations } from 'next-intl/server';

import { TODO_OWNERS, TODO_PRIORITIES } from '@/domain/enums';
import { todoFilterSchema } from '@/domain/schemas';
import { can } from '@/lib/auth/rbac';
import * as session from '@/lib/auth/session';
import { readToken } from '@/lib/security/csrf';
import { FilterForm } from '@/components/FilterForm';
import { listTodos } from '@/server/data/board';

import { BoardClient } from './BoardClient';

export default async function BoardPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const active = await session.current();
  if (!active) return null;

  const raw = await searchParams;
  const filter = todoFilterSchema.parse({ owner: raw.owner, priority: raw.priority });

  const [t, tCommon] = await Promise.all([getTranslations('board'), getTranslations('common')]);
  const todos = listTodos(filter);
  const canWrite = can(active.user.role, 'board.write');
  const csrfToken = await readToken(active.sessionId);

  return (
    <>
      <FilterForm>
        <select name="owner" defaultValue={filter.owner}>
          <option value="">{t('filterOwner')}</option>
          {TODO_OWNERS.map((owner) => (
            <option key={owner} value={owner}>
              {owner}
            </option>
          ))}
        </select>
        <select name="priority" defaultValue={filter.priority}>
          <option value="">{t('filterPriority')}</option>
          {TODO_PRIORITIES.map((priority) => (
            <option key={priority} value={priority}>
              {priority}
            </option>
          ))}
        </select>
        <noscript>
          <button type="submit">{tCommon('filter')}</button>
        </noscript>
      </FilterForm>

      <BoardClient items={todos} canWrite={canWrite} csrfToken={csrfToken} />
    </>
  );
}
