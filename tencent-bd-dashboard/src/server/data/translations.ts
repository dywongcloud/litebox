import 'server-only';

import { and, eq } from 'drizzle-orm';

import { db } from '@/db/client';
import { translations } from '@/db/schema';
import type { NewTranslation, Translation } from '@/db/schema';
import type { Locale } from '@/domain/enums';

/**
 * Translation memory.
 *
 * See `src/db/schema.ts` for why source text is never overwritten in place: a
 * translation is a separate, versioned row so provenance and staleness survive
 * independently of the field it translates.
 */

export function getTranslation(
  entityType: string,
  entityId: number,
  field: string,
  locale: Locale,
): Translation | undefined {
  return db
    .select()
    .from(translations)
    .where(
      and(
        eq(translations.entityType, entityType),
        eq(translations.entityId, entityId),
        eq(translations.field, field),
        eq(translations.locale, locale),
      ),
    )
    .get();
}

export function listTranslationsForEntity(entityType: string, entityId: number): Translation[] {
  return db
    .select()
    .from(translations)
    .where(and(eq(translations.entityType, entityType), eq(translations.entityId, entityId)))
    .all();
}

export function upsertTranslation(values: NewTranslation): Translation {
  const existing = getTranslation(
    values.entityType,
    values.entityId,
    values.field,
    values.locale,
  );

  if (existing) {
    return db
      .update(translations)
      .set({
        value: values.value,
        sourceLocale: values.sourceLocale,
        sourceHash: values.sourceHash,
        origin: values.origin,
        status: values.status ?? 'needs-review',
        reviewedBy: null,
        reviewedAt: null,
        updatedAt: new Date(),
      })
      .where(eq(translations.id, existing.id))
      .returning()
      .get();
  }

  return db.insert(translations).values(values).returning().get();
}

export function listNeedingReview(): Translation[] {
  return db.select().from(translations).where(eq(translations.status, 'needs-review')).all();
}

export function reviewTranslation(
  id: number,
  status: 'approved' | 'needs-review',
  reviewerId: number,
  value?: string,
): Translation | undefined {
  return db
    .update(translations)
    .set({
      status,
      ...(value === undefined ? {} : { value }),
      reviewedBy: reviewerId,
      reviewedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(translations.id, id))
    .returning()
    .get();
}
