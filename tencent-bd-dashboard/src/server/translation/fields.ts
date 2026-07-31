import type { TranslatableEntity } from '@/domain/schemas';

/**
 * Which fields of each entity may be translated, and how to read/write them.
 *
 * A field allowlist rather than "any string column": translating `notes`
 * freely is fine, but translating `priority` (an enum) would be nonsensical
 * and translating `source` (a citation) would misrepresent where a claim came
 * from. Keeping the list explicit is also what lets `translationRequestSchema`
 * reject an unknown field before it reaches a lookup.
 */
export const TRANSLATABLE_FIELDS: Record<TranslatableEntity, readonly string[]> = {
  product: [
    'description',
    'useCases',
    'painPoints',
    'strengths',
    'weaknesses',
    'productEntry',
    'bdMotion',
    'solutionStory',
    'tencentEdge',
    'messagingTechnical',
    'messagingBusiness',
    'messagingExecutive',
    'messagingSafeClaim',
  ],
  account: ['pain', 'trigger', 'nextAction', 'notes'],
  motion: [
    'triggerSignals',
    'icp',
    'discoveryQuestions',
    'wedgeProduct',
    'pocStrategy',
    'successMetrics',
    'expansionPath',
    'risks',
  ],
  todo: ['detail'],
};

export function isTranslatableField(entity: TranslatableEntity, field: string): boolean {
  return (TRANSLATABLE_FIELDS[entity] as readonly string[]).includes(field);
}
