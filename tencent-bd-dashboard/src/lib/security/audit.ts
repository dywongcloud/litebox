import 'server-only';

import { db } from '@/db/client';
import { auditLog } from '@/db/schema';

import { pseudonymise } from './crypto';

/**
 * Append-only audit trail.
 *
 * Every authentication event and every business mutation records one entry.
 * Nothing in the application updates or deletes from this table, so the record
 * of who changed what survives even a full rollback of the data it describes.
 */

export type AuditAction =
  | 'auth.login.success'
  | 'auth.login.failure'
  | 'auth.login.locked'
  | 'auth.login.rate-limited'
  | 'auth.logout'
  | 'auth.session.rejected'
  | 'auth.password.changed'
  | 'user.created'
  | 'user.updated'
  | 'user.deactivated'
  | 'product.created'
  | 'product.updated'
  | 'product.deleted'
  | 'product.evidence.saved'
  | 'product.story.saved'
  | 'product.score.saved'
  | 'account.created'
  | 'account.updated'
  | 'account.deleted'
  | 'account.research.saved'
  | 'todo.created'
  | 'todo.updated'
  | 'todo.deleted'
  | 'sop.saved'
  | 'motion.created'
  | 'motion.updated'
  | 'motion.deleted'
  | 'review.answered'
  | 'translation.requested'
  | 'translation.approved'
  | 'translation.rejected'
  | 'catalog.sync.started'
  | 'catalog.sync.finished'
  | 'catalog.sync.failed'
  | 'data.exported'
  | 'data.imported'
  | 'data.reset';

export interface AuditInput {
  readonly action: AuditAction;
  readonly actorUserId?: number | null;
  readonly actorEmail?: string;
  readonly entityType?: string;
  readonly entityId?: string | number;
  readonly metadata?: Record<string, unknown>;
  readonly ip?: string;
  readonly outcome?: 'success' | 'failure';
}

/** Keys that must never reach the audit table even if a caller passes them. */
const REDACTED_KEYS = new Set([
  'password',
  'newPassword',
  'currentPassword',
  'passwordHash',
  'token',
  'secret',
  'secretId',
  'secretKey',
  'authorization',
  'cookie',
  'csrf',
]);

/**
 * Strip secrets and bound the size of caller-supplied metadata.
 *
 * Audit metadata is written from many call sites; treating it as untrusted here
 * means one careless caller cannot persist a credential, and a large payload
 * cannot bloat the table.
 */
function sanitiseMetadata(metadata: Record<string, unknown> | undefined): string {
  if (!metadata) return '{}';

  const safe: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(metadata)) {
    if (REDACTED_KEYS.has(key)) {
      safe[key] = '[redacted]';
      continue;
    }

    if (value === null || value === undefined) {
      safe[key] = null;
    } else if (typeof value === 'string') {
      safe[key] = value.length > 500 ? `${value.slice(0, 500)}...` : value;
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      safe[key] = value;
    } else if (Array.isArray(value)) {
      safe[key] = value.slice(0, 50).map((item) => (typeof item === 'object' ? '[object]' : item));
    } else {
      safe[key] = '[object]';
    }
  }

  const serialised = JSON.stringify(safe);
  return serialised.length > 4000 ? JSON.stringify({ truncated: true }) : serialised;
}

/**
 * Write one audit entry.
 *
 * Never throws. An audit failure must not roll back or block the operation it
 * describes -- losing a log line is bad, failing a user's save because logging
 * broke is worse. Failures go to stderr where the platform collects them.
 */
export function record(input: AuditInput): void {
  try {
    db.insert(auditLog)
      .values({
        actorUserId: input.actorUserId ?? null,
        actorEmail: input.actorEmail ?? '',
        action: input.action,
        entityType: input.entityType ?? '',
        entityId: input.entityId === undefined ? '' : String(input.entityId),
        metadata: sanitiseMetadata(input.metadata),
        ipHash: pseudonymise(input.ip ?? ''),
        outcome: input.outcome ?? 'success',
      })
      .run();
  } catch (error) {
    console.error('[audit] failed to write entry', {
      action: input.action,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}
