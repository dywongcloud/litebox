import 'server-only';

import * as OpenCC from 'opencc-js';

import type { Translation } from '@/db/schema';
import type { Locale } from '@/domain/enums';
import { TRANSLATION_MAX_CHARS, type TranslatableEntity } from '@/domain/schemas';
import { hasTencentCredentials } from '@/lib/env';
import { sha256 } from '@/lib/security/crypto';
import { upsertTranslation } from '@/server/data/translations';
import { translateText } from '@/server/tencent/translate-client';

import { isTranslatableField } from './fields';
import { getSourceText } from './source';

/**
 * Locale-pair translation.
 *
 * Two independent mechanisms cover the three-locale matrix, chosen so the
 * mechanism used is always the weakest one that is actually correct for the
 * pair -- never machine-translating a same-script conversion, and never
 * pretending script conversion can cross the English boundary:
 *
 *   - zh-Hans <-> zh-Hant: deterministic script conversion (`opencc-js`),
 *     no network call, no meaning change, so it never needs human review.
 *   - en <-> zh (either script): the Tencent Cloud TMT `TextTranslate` API,
 *     which only knows a single `zh` code. Traditional input is normalised to
 *     Simplified before the call and Traditional output is derived from the
 *     Simplified result afterwards, so the API boundary is always exactly
 *     `en <-> zh-Hans` and the script handling is explicit rather than assumed.
 *
 * Every result is content-addressed by `sourceHash`: a later change to the
 * source text invalidates a stored translation rather than serving it silently
 * stale (see `translations.stale` handling in `getTranslationStatus`).
 */

const toSimplified = OpenCC.Converter({ from: 'tw', to: 'cn' });
const toTraditional = OpenCC.Converter({ from: 'cn', to: 'tw' });

export type TranslationOutcome =
  | { ok: true; translation: Translation }
  | { ok: false; reason: 'unavailable' | 'too-long' | 'invalid-field' | 'not-found' | 'upstream-error'; detail?: string };

function isZh(locale: Locale): boolean {
  return locale === 'zh-Hans' || locale === 'zh-Hant';
}

/** Normalise text to Simplified for the API boundary, only when needed. */
function normaliseForApi(text: string, locale: Locale): string {
  return locale === 'zh-Hant' ? toSimplified(text) : text;
}

export async function translateField(
  entityType: TranslatableEntity,
  entityId: number,
  field: string,
  sourceLocale: Locale,
  targetLocale: Locale,
): Promise<TranslationOutcome> {
  if (!isTranslatableField(entityType, field)) {
    return { ok: false, reason: 'invalid-field' };
  }

  const sourceText = getSourceText(entityType, entityId, field);
  if (sourceText === null) {
    return { ok: false, reason: 'not-found' };
  }

  if (sourceText.length > TRANSLATION_MAX_CHARS) {
    return { ok: false, reason: 'too-long', detail: String(sourceText.length) };
  }

  if (sourceText.trim() === '') {
    // Nothing to translate; store the empty result rather than erroring, so
    // an empty field does not block a batch translation of the rest.
    const translation = upsertTranslation({
      entityType,
      entityId,
      field,
      locale: targetLocale,
      value: '',
      sourceLocale,
      sourceHash: sha256(''),
      origin: 'script-conversion',
      status: 'approved',
    });
    return { ok: true, translation };
  }

  const sourceHash = sha256(sourceText);

  // Pure script conversion: both locales are Chinese.
  if (isZh(sourceLocale) && isZh(targetLocale)) {
    const value = targetLocale === 'zh-Hant' ? toTraditional(sourceText) : toSimplified(sourceText);
    const translation = upsertTranslation({
      entityType,
      entityId,
      field,
      locale: targetLocale,
      value,
      sourceLocale,
      sourceHash,
      origin: 'script-conversion',
      status: 'approved',
    });
    return { ok: true, translation };
  }

  // Crossing the English boundary requires the machine-translation API.
  if (!hasTencentCredentials) {
    return { ok: false, reason: 'unavailable' };
  }

  const apiSource = normaliseForApi(sourceText, sourceLocale);
  const apiSourceCode = sourceLocale === 'en' ? 'en' : 'zh';
  const apiTargetCode = targetLocale === 'en' ? 'en' : 'zh';

  const result = await translateText(apiSource, apiSourceCode, apiTargetCode);
  if (!result.ok) {
    return { ok: false, reason: 'upstream-error', detail: result.message };
  }

  const value = targetLocale === 'zh-Hant' ? toTraditional(result.data.text) : result.data.text;

  const translation = upsertTranslation({
    entityType,
    entityId,
    field,
    locale: targetLocale,
    value,
    sourceLocale,
    sourceHash,
    origin: 'machine',
    status: 'needs-review',
  });

  return { ok: true, translation };
}

/** Whether a stored translation is stale relative to the current source text. */
export function isStale(
  translation: Pick<Translation, 'sourceHash'>,
  entityType: TranslatableEntity,
  entityId: number,
  field: string,
): boolean {
  const current = getSourceText(entityType, entityId, field);
  if (current === null) return false;
  return sha256(current) !== translation.sourceHash;
}
