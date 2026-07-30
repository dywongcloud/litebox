import { CsrfError, RateLimitedError, UnauthenticatedError } from '@/lib/auth/guard';
import { ForbiddenError } from '@/lib/auth/rbac';
import type { FieldErrors } from '@/domain/schemas';

/**
 * Shared shape returned by every form-backed Server Action, consumed via
 * `useActionState` on the client. `errors` is field-keyed for inline display;
 * `message` is a form-level notice (typically a guard rejection).
 */
export interface FormActionState {
  readonly errors?: FieldErrors;
  readonly message?: string;
  readonly success?: boolean;
}

/**
 * Map a `requireMutation`/`requireRead` rejection to the message shown in the
 * form. Deliberately coarse -- see `@/lib/auth/guard`'s `describeError` for why
 * the reasons are not more specific.
 */
export function describeGuardError(error: unknown): string {
  if (error instanceof UnauthenticatedError) return 'Your session has expired. Please sign in again.';
  if (error instanceof ForbiddenError) return 'You do not have permission to perform this action.';
  if (error instanceof CsrfError) return 'This request could not be verified. Please reload and retry.';
  if (error instanceof RateLimitedError) return 'Too many requests. Please wait a moment and try again.';
  return 'Something went wrong. Please try again.';
}
