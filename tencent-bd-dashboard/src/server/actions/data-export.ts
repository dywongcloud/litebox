'use server';

import { desc } from 'drizzle-orm';

import { db } from '@/db/client';
import {
  accountResearch,
  accounts,
  auditLog,
  motions,
  productEvidence,
  products,
  sopSteps,
  todos,
} from '@/db/schema';
import * as audit from '@/lib/security/audit';
import { requireMutation, requireRead } from '@/lib/auth/guard';

import { describeGuardError } from './shared';

/**
 * Whole-corpus export.
 *
 * A Server Action rather than a Route Handler: it needs the same session,
 * CSRF and rate-limit gate as every other mutation-adjacent operation (an
 * export is read-only against the data, but it is still an operation worth
 * rate-limiting and auditing, since a scripted loop against it is a data
 * exfiltration path).
 *
 * Returns a plain object rather than triggering a download directly -- Server
 * Actions cannot set a `Content-Disposition` response header, so the calling
 * client component builds the Blob and file download from this payload.
 */
export interface ExportResult {
  readonly ok: boolean;
  readonly message?: string;
  readonly data?: {
    readonly exportedAt: string;
    readonly products: unknown[];
    readonly productEvidence: unknown[];
    readonly accounts: unknown[];
    readonly accountResearch: unknown[];
    readonly todos: unknown[];
    readonly sopSteps: unknown[];
    readonly motions: unknown[];
  };
}

export async function exportAllData(formData: FormData): Promise<ExportResult> {
  let actor;
  try {
    actor = await requireMutation('data.export', formData, { bucket: 'export' });
  } catch (error) {
    return { ok: false, message: describeGuardError(error) };
  }

  const data = {
    exportedAt: new Date().toISOString(),
    products: db.select().from(products).all(),
    productEvidence: db.select().from(productEvidence).all(),
    accounts: db.select().from(accounts).all(),
    accountResearch: db.select().from(accountResearch).all(),
    todos: db.select().from(todos).all(),
    sopSteps: db.select().from(sopSteps).orderBy(sopSteps.position).all(),
    motions: db.select().from(motions).all(),
  };

  audit.record({ action: 'data.exported', actorUserId: actor.user.id });

  return { ok: true, data };
}

export interface AuditPage {
  readonly ok: boolean;
  readonly message?: string;
  readonly entries?: Array<{
    readonly id: number;
    readonly action: string;
    readonly actorEmail: string;
    readonly entityType: string;
    readonly entityId: string;
    readonly outcome: string;
    readonly createdAt: string;
  }>;
}

/** Recent audit entries for the admin panel. Read-only: no CSRF/rate-limit gate. */
export async function loadAuditLog(): Promise<AuditPage> {
  try {
    await requireRead('audit.read');
  } catch (error) {
    return { ok: false, message: describeGuardError(error) };
  }

  const rows = db.select().from(auditLog).orderBy(desc(auditLog.createdAt)).limit(200).all();

  return {
    ok: true,
    entries: rows.map((r) => ({
      id: r.id,
      action: r.action,
      actorEmail: r.actorEmail,
      entityType: r.entityType,
      entityId: r.entityId,
      outcome: r.outcome,
      createdAt: r.createdAt.toISOString(),
    })),
  };
}
