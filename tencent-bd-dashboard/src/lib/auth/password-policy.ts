import { z } from 'zod';

/**
 * Password policy.
 *
 * Length does more for resistance to offline cracking than character-class
 * rules do, so the floor is 12 rather than 8. The class requirements are kept
 * because they cheaply rule out the most common weak choices, and a deny-list
 * catches the handful of long-but-obvious passwords that would otherwise pass
 * every mechanical check.
 */

export const PASSWORD_MIN_LENGTH = 12;

/**
 * bcrypt's 72-byte input truncation is not in play here (scrypt has no such
 * limit), but an unbounded password is a cheap denial-of-service: every
 * verification would hash it. 200 characters is far above any real passphrase.
 */
export const PASSWORD_MAX_LENGTH = 200;

const COMMON_PASSWORDS = new Set([
  'password',
  'password1',
  'password123',
  'passw0rd',
  'qwertyuiop',
  'administrator',
  'letmein12345',
  'iloveyou1234',
  'changeme1234',
  'welcome12345',
  'tencentcloud',
  'tencentcloud1',
]);

export interface PasswordCheck {
  readonly ok: boolean;
  readonly problems: readonly string[];
}

/**
 * Evaluate a password, returning every problem at once.
 *
 * Reporting all failures together avoids the whack-a-mole loop where a user
 * fixes the length only to be told about the missing digit on the next attempt.
 */
export function check(password: string): PasswordCheck {
  const problems: string[] = [];
  const normalised = password.normalize('NFKC');

  if (normalised.length < PASSWORD_MIN_LENGTH) {
    problems.push(`Must be at least ${PASSWORD_MIN_LENGTH} characters`);
  }
  if (normalised.length > PASSWORD_MAX_LENGTH) {
    problems.push(`Must be at most ${PASSWORD_MAX_LENGTH} characters`);
  }
  if (!/[a-z]/.test(normalised)) {
    problems.push('Must contain a lowercase letter');
  }
  if (!/[A-Z]/.test(normalised)) {
    problems.push('Must contain an uppercase letter');
  }
  if (!/[0-9]/.test(normalised)) {
    problems.push('Must contain a digit');
  }
  if (!/[^A-Za-z0-9]/.test(normalised)) {
    problems.push('Must contain a symbol');
  }

  // Strip non-letters before the deny-list lookup so `P@ssword123` is caught
  // alongside `password`.
  const reduced = normalised.toLowerCase().replace(/[^a-z]/g, '');
  if (COMMON_PASSWORDS.has(normalised.toLowerCase()) || COMMON_PASSWORDS.has(reduced)) {
    problems.push('Is too common; choose an unrelated passphrase');
  }

  // Three or more identical consecutive characters is a strong signal of a
  // padded rather than chosen password.
  if (/(.)\1{2,}/.test(normalised)) {
    problems.push('Must not repeat the same character three times in a row');
  }

  return { ok: problems.length === 0, problems };
}

/** Zod binding, so the policy is enforced identically wherever it is used. */
export const passwordSchema = z
  .string()
  .min(PASSWORD_MIN_LENGTH)
  .max(PASSWORD_MAX_LENGTH)
  .superRefine((value, ctx) => {
    for (const problem of check(value).problems) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: problem });
    }
  });
