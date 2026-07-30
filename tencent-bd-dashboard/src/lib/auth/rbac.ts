import type { UserRole } from '@/domain/enums';

/**
 * Role-based access control.
 *
 * Permissions are named capabilities rather than table names, so a change to
 * the data model does not silently widen what a role can do. The mapping is a
 * total `Record`, which means adding a permission fails to compile until every
 * role has been considered for it -- there is no implicit deny-by-omission that
 * someone could mistake for a decision.
 */

export type Permission =
  | 'catalog.read'
  | 'catalog.write'
  | 'catalog.delete'
  | 'catalog.sync'
  | 'account.read'
  | 'account.write'
  | 'account.delete'
  | 'board.read'
  | 'board.write'
  | 'playbook.read'
  | 'playbook.write'
  | 'review.read'
  | 'review.write'
  | 'translation.request'
  | 'translation.approve'
  | 'data.export'
  | 'data.import'
  | 'data.reset'
  | 'audit.read'
  | 'user.manage';

const VIEWER: readonly Permission[] = [
  'catalog.read',
  'account.read',
  'board.read',
  'playbook.read',
  'review.read',
  'data.export',
];

const EDITOR: readonly Permission[] = [
  ...VIEWER,
  'catalog.write',
  'catalog.delete',
  'catalog.sync',
  'account.write',
  'account.delete',
  'board.write',
  'playbook.write',
  'review.write',
  'translation.request',
];

const ADMIN: readonly Permission[] = [
  ...EDITOR,
  'translation.approve',
  'data.import',
  'data.reset',
  'audit.read',
  'user.manage',
];

const PERMISSIONS: Record<UserRole, ReadonlySet<Permission>> = {
  viewer: new Set(VIEWER),
  editor: new Set(EDITOR),
  admin: new Set(ADMIN),
};

export function can(role: UserRole, permission: Permission): boolean {
  return PERMISSIONS[role].has(permission);
}

export function permissionsFor(role: UserRole): readonly Permission[] {
  return [...PERMISSIONS[role]];
}

/**
 * Thrown when an authenticated user lacks a permission. Distinct from the
 * unauthenticated case so the caller can answer 403 rather than 401 -- telling
 * a signed-in user to sign in again is a dead end.
 */
export class ForbiddenError extends Error {
  readonly permission: Permission;

  constructor(permission: Permission) {
    super(`Missing permission: ${permission}`);
    this.name = 'ForbiddenError';
    this.permission = permission;
  }
}
