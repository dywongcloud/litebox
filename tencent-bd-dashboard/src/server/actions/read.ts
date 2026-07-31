'use server';

import { idSchema } from '@/domain/schemas';
import { requireRead } from '@/lib/auth/guard';
import { getProductEvidence } from '@/server/data/products';
import { listTranslationsForEntity } from '@/server/data/translations';
import type { ProductEvidence, Translation } from '@/db/schema';

import { describeGuardError } from './shared';

/**
 * On-demand reads for data that is deliberately excluded from the main list
 * queries (evidence rows, translation memory) to keep those queries cheap for
 * 181+ rows. Fetched lazily by client components only when a modal that needs
 * them actually opens.
 */

export interface EvidenceResult {
  readonly ok: boolean;
  readonly message?: string;
  readonly rows?: ProductEvidence[];
}

export async function loadProductEvidence(productId: number): Promise<EvidenceResult> {
  try {
    await requireRead('catalog.read');
  } catch (error) {
    return { ok: false, message: describeGuardError(error) };
  }

  const id = idSchema.safeParse(productId);
  if (!id.success) return { ok: false, message: 'Invalid product.' };

  return { ok: true, rows: getProductEvidence(id.data) };
}

export interface TranslationsResult {
  readonly ok: boolean;
  readonly message?: string;
  readonly translations?: Translation[];
}

export async function loadTranslations(entityType: string, entityId: number): Promise<TranslationsResult> {
  try {
    await requireRead('catalog.read');
  } catch (error) {
    return { ok: false, message: describeGuardError(error) };
  }

  const id = idSchema.safeParse(entityId);
  if (!id.success) return { ok: false, message: 'Invalid record.' };

  return { ok: true, translations: listTranslationsForEntity(entityType, id.data) };
}
