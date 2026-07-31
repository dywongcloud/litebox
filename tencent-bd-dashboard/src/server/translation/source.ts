import 'server-only';

import { getAccount } from '@/server/data/accounts';
import { getMotion, getTodo } from '@/server/data/board';
import { getProduct } from '@/server/data/products';
import type { TranslatableEntity } from '@/domain/schemas';

import { isTranslatableField } from './fields';

/**
 * Read the current value of a translatable field.
 *
 * `field` must already have passed `isTranslatableField` -- checked again here
 * as a second gate, since this function is the one that turns a string into a
 * property access, and a caller that skipped validation must still fail closed
 * rather than reflect an arbitrary column.
 */
export function getSourceText(
  entityType: TranslatableEntity,
  entityId: number,
  field: string,
): string | null {
  if (!isTranslatableField(entityType, field)) return null;

  switch (entityType) {
    case 'product': {
      const row = getProduct(entityId);
      return row ? readField(row, field) : null;
    }
    case 'account': {
      const row = getAccount(entityId);
      return row ? readField(row, field) : null;
    }
    case 'motion': {
      const row = getMotion(entityId);
      return row ? readField(row, field) : null;
    }
    case 'todo': {
      const row = getTodo(entityId);
      return row ? readField(row, field) : null;
    }
    default:
      return null;
  }
}

function readField(row: Record<string, unknown>, field: string): string | null {
  const value = row[field];
  return typeof value === 'string' ? value : null;
}
