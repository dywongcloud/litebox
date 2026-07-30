'use server';

import { revalidatePath } from 'next/cache';

import {
  evidenceStudioSchema,
  formDataToObject,
  idSchema,
  priorityScoreSchema,
  productSchema,
  productStorySchema,
  toFieldErrors,
} from '@/domain/schemas';
import { PRIORITY_SCORE_TOTAL_MAX } from '@/domain/enums';
import * as audit from '@/lib/security/audit';
import { requireMutation } from '@/lib/auth/guard';
import {
  createProduct,
  deleteProduct,
  getProduct,
  replaceEvidence,
  updateProduct,
} from '@/server/data/products';
import { syncCatalog } from '@/server/catalog/sync';

import { describeGuardError as actorMessage, type FormActionState } from './shared';

export async function saveProduct(_prev: FormActionState, formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('catalog.write', formData);
  } catch (error) {
    return { message: actorMessage(error) };
  }

  const raw = formDataToObject(formData);
  const parsed = productSchema.safeParse(raw);
  if (!parsed.success) return { errors: toFieldErrors(parsed.error) };

  const idField = formData.get('id');
  const id = idField ? idSchema.safeParse(idField) : undefined;

  if (id?.success) {
    const existing = getProduct(id.data);
    if (!existing) return { message: 'That product no longer exists.' };
    updateProduct(id.data, parsed.data);
    audit.record({ action: 'product.updated', actorUserId: actor.user.id, entityType: 'product', entityId: id.data });
  } else {
    const created = createProduct(parsed.data);
    audit.record({ action: 'product.created', actorUserId: actor.user.id, entityType: 'product', entityId: created.id });
  }

  revalidatePath('/[locale]/products', 'page');
  return { success: true };
}

export async function removeProduct(formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('catalog.delete', formData);
  } catch (error) {
    return { message: actorMessage(error) };
  }

  const id = idSchema.safeParse(formData.get('id'));
  if (!id.success) return { message: 'Invalid product.' };

  const deleted = deleteProduct(id.data);
  if (deleted) {
    audit.record({ action: 'product.deleted', actorUserId: actor.user.id, entityType: 'product', entityId: id.data });
  }

  revalidatePath('/[locale]/products', 'page');
  return { success: deleted };
}

export async function saveProductStory(_prev: FormActionState, formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('catalog.write', formData);
  } catch (error) {
    return { message: actorMessage(error) };
  }

  const id = idSchema.safeParse(formData.get('id'));
  if (!id.success) return { message: 'Invalid product.' };

  const parsed = productStorySchema.safeParse(formDataToObject(formData));
  if (!parsed.success) return { errors: toFieldErrors(parsed.error) };

  const existing = getProduct(id.data);
  if (!existing) return { message: 'That product no longer exists.' };

  updateProduct(id.data, parsed.data);
  audit.record({ action: 'product.story.saved', actorUserId: actor.user.id, entityType: 'product', entityId: id.data });

  revalidatePath('/[locale]/products', 'page');
  return { success: true };
}

export async function savePriorityScore(_prev: FormActionState, formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('catalog.write', formData);
  } catch (error) {
    return { message: actorMessage(error) };
  }

  const id = idSchema.safeParse(formData.get('id'));
  if (!id.success) return { message: 'Invalid product.' };

  const parsed = priorityScoreSchema.safeParse(formDataToObject(formData));
  if (!parsed.success) return { errors: toFieldErrors(parsed.error) };

  const existing = getProduct(id.data);
  if (!existing) return { message: 'That product no longer exists.' };

  const { demand, rightToWin, entry, poc, expansion, revenue, rationale, validation } = parsed.data;
  const total = demand + rightToWin + entry + poc + expansion + revenue;

  // Mirrors the source app's recommendation curve: a score above 80% of the
  // maximum suggests P1, above 55% suggests P2, otherwise P3. The rep can
  // still override the resulting `priority` field independently; this only
  // sets the initial suggestion.
  const priority = total >= PRIORITY_SCORE_TOTAL_MAX * 0.8 ? 'P1' : total >= PRIORITY_SCORE_TOTAL_MAX * 0.55 ? 'P2' : 'P3';

  updateProduct(id.data, {
    scoreDemand: demand,
    scoreRightToWin: rightToWin,
    scoreEntry: entry,
    scorePoc: poc,
    scoreExpansion: expansion,
    scoreRevenue: revenue,
    scoreRationale: rationale,
    scoreValidation: validation,
    priority,
  });

  audit.record({
    action: 'product.score.saved',
    actorUserId: actor.user.id,
    entityType: 'product',
    entityId: id.data,
    metadata: { total, priority },
  });

  revalidatePath('/[locale]/products', 'page');
  return { success: true };
}

export async function saveEvidenceStudio(_prev: FormActionState, formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('catalog.write', formData);
  } catch (error) {
    return { message: actorMessage(error) };
  }

  const id = idSchema.safeParse(formData.get('id'));
  if (!id.success) return { message: 'Invalid product.' };

  const existing = getProduct(id.data);
  if (!existing) return { message: 'That product no longer exists.' };

  // The evidence table arrives as one JSON blob rather than indexed fields:
  // it is a variable-length repeating structure, and FormData has no native
  // array-of-objects encoding that survives add/remove/reorder cleanly.
  const rowsRaw = formData.get('rows');
  let rowsParsed: unknown;
  try {
    rowsParsed = JSON.parse(typeof rowsRaw === 'string' ? rowsRaw : '[]');
  } catch {
    return { message: 'Evidence rows were not submitted correctly. Please reload and retry.' };
  }

  const parsed = evidenceStudioSchema.safeParse({ ...formDataToObject(formData), rows: rowsParsed });
  if (!parsed.success) return { errors: toFieldErrors(parsed.error) };

  replaceEvidence(id.data, parsed.data.rows, {
    messagingTechnical: parsed.data.messagingTechnical,
    messagingBusiness: parsed.data.messagingBusiness,
    messagingExecutive: parsed.data.messagingExecutive,
    messagingSafeClaim: parsed.data.messagingSafeClaim,
    discovery: parsed.data.discovery,
    buyingSignals: parsed.data.buyingSignals,
    redFlags: parsed.data.redFlags,
    proofRequired: parsed.data.proofRequired,
    objections: parsed.data.objections,
    replacements: parsed.data.replacements,
    learningChecklist: parsed.data.learningChecklist,
  });

  audit.record({
    action: 'product.evidence.saved',
    actorUserId: actor.user.id,
    entityType: 'product',
    entityId: id.data,
    metadata: { rowCount: parsed.data.rows.length },
  });

  revalidatePath('/[locale]/products', 'page');
  return { success: true };
}

export async function runCatalogSync(_prev: FormActionState, formData: FormData): Promise<FormActionState> {
  let actor;
  try {
    actor = await requireMutation('catalog.sync', formData, { bucket: 'catalog-sync' });
  } catch (error) {
    return { message: actorMessage(error) };
  }

  audit.record({ action: 'catalog.sync.started', actorUserId: actor.user.id });
  const result = await syncCatalog(actor.user.id);

  audit.record({
    action: result.ok ? 'catalog.sync.finished' : 'catalog.sync.failed',
    actorUserId: actor.user.id,
    metadata: { seen: result.seen, created: result.created, updated: result.updated, error: result.error },
    outcome: result.ok ? 'success' : 'failure',
  });

  revalidatePath('/[locale]/products', 'page');

  return result.ok
    ? { success: true, message: `Sync complete: ${result.created} created, ${result.updated} updated, ${result.seen} seen.` }
    : { message: `Sync failed: ${result.error ?? 'unknown error'}` };
}
