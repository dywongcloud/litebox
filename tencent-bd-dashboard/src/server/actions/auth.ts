'use server';

import { getLocale } from 'next-intl/server';
import { redirect } from 'next/navigation';

import { passwordSchema } from '@/lib/auth/password-policy';
import * as session from '@/lib/auth/session';
import { env } from '@/lib/env';
import * as audit from '@/lib/security/audit';
import { dummyVerify, hashPassword, verifyPassword } from '@/lib/security/crypto';
import { CSRF_FIELD, verify as verifyCsrf } from '@/lib/security/csrf';
import * as rateLimit from '@/lib/security/rate-limit';
import { context, isSameOrigin } from '@/lib/security/request';
import { formDataToObject, loginSchema, toFieldErrors, type FieldErrors } from '@/domain/schemas';
import { findByEmail, recordLoginFailure, recordLoginSuccess, setPassword } from '@/server/data/users';

/**
 * Authentication actions.
 *
 * `login` cannot use `requireMutation` -- there is no session yet, that is the
 * whole point -- so it re-implements the same defence-in-depth stack by hand:
 * origin check, rate limiting on two independent axes, uniform timing, and
 * audit logging of every outcome including failures.
 */

export interface LoginState {
  readonly errors?: FieldErrors;
  readonly message?: string;
}

export async function login(_prev: LoginState, formData: FormData): Promise<LoginState> {
  if (!(await isSameOrigin())) {
    return { message: 'This request could not be verified. Please reload and retry.' };
  }

  const parsed = loginSchema.safeParse(formDataToObject(formData));
  if (!parsed.success) {
    return { errors: toFieldErrors(parsed.error) };
  }

  const { email, password, next } = parsed.data;
  const ctx = await context();

  // Rate-limit on both the account and the source IP, so an attacker cannot
  // evade the per-account limit by spreading guesses across many accounts from
  // one IP, nor the per-IP limit by spreading one account's guesses across
  // many source addresses (much harder, but the per-account limit alone still
  // catches that case).
  const limited = rateLimit.consumeAll([
    ['login', email],
    ['login-ip', ctx.ip],
  ]);

  if (!limited.allowed) {
    audit.record({ action: 'auth.login.rate-limited', actorEmail: email, ip: ctx.ip, outcome: 'failure' });
    return { message: 'Too many sign-in attempts. Please wait a few minutes and try again.' };
  }

  const user = findByEmail(email);

  // No account: burn the same time a real verification would take, so
  // response latency cannot be used to enumerate valid emails.
  if (!user) {
    await dummyVerify();
    audit.record({ action: 'auth.login.failure', actorEmail: email, ip: ctx.ip, outcome: 'failure' });
    return { message: 'Email or password is incorrect.' };
  }

  if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
    audit.record({
      action: 'auth.login.locked',
      actorUserId: user.id,
      actorEmail: email,
      ip: ctx.ip,
      outcome: 'failure',
    });
    const minutes = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60_000);
    return { message: `Too many failed attempts. Try again in ${minutes} minutes.` };
  }

  if (!user.isActive) {
    // Still run a verification so response timing does not distinguish a
    // deactivated account from an active one with a wrong password.
    await verifyPassword(password, user.passwordHash);
    audit.record({
      action: 'auth.login.failure',
      actorUserId: user.id,
      actorEmail: email,
      ip: ctx.ip,
      outcome: 'failure',
    });
    return { message: 'This account has been deactivated. Contact an administrator.' };
  }

  const valid = await verifyPassword(password, user.passwordHash);
  if (!valid) {
    const { failedLoginCount, lockedUntil } = recordLoginFailure(
      user.id,
      env.LOGIN_MAX_ATTEMPTS,
      env.LOGIN_LOCKOUT_SECONDS,
    );
    audit.record({
      action: lockedUntil ? 'auth.login.locked' : 'auth.login.failure',
      actorUserId: user.id,
      actorEmail: email,
      ip: ctx.ip,
      metadata: { failedLoginCount },
      outcome: 'failure',
    });
    return { message: 'Email or password is incorrect.' };
  }

  recordLoginSuccess(user.id);
  rateLimit.reset('login', email);
  rateLimit.reset('login-ip', ctx.ip);
  await session.create(user.id, ctx);

  audit.record({ action: 'auth.login.success', actorUserId: user.id, actorEmail: email, ip: ctx.ip });

  // Only a same-site path is ever honoured, so this can never become an open
  // redirect via a crafted `next` value. The fallback is built fully
  // locale-prefixed (rather than a bare `/`) because a Server Action's
  // redirect is followed by the client router directly -- it does not
  // reliably re-enter the proxy/middleware the way a fresh browser navigation
  // does, so an unprefixed path like `/login` can dead-end instead of being
  // redirected on to `/en/login`.
  const destination = next && next.startsWith('/') && !next.startsWith('//') ? next : `/${await getLocale()}/products`;
  redirect(destination);
}

export async function logout(formData: FormData): Promise<void> {
  const active = await session.current();

  // Same defence-in-depth as every other mutation: cross-origin and unverified
  // requests are rejected before anything is revoked. A forged sign-out is a
  // nuisance rather than a data breach, but "logout is low stakes" is not a
  // reason to skip the gate every other mutation goes through.
  const originOk = await isSameOrigin();
  const submitted = formData.get(CSRF_FIELD);
  const csrfOk = active ? await verifyCsrf(typeof submitted === 'string' ? submitted : null, active.sessionId) : true;

  if (active && originOk && csrfOk) {
    const ctx = await context();
    audit.record({ action: 'auth.logout', actorUserId: active.user.id, actorEmail: active.user.email, ip: ctx.ip });
    await session.destroy();
  } else if (active) {
    audit.record({
      action: 'auth.session.rejected',
      actorUserId: active.user.id,
      actorEmail: active.user.email,
      metadata: { reason: originOk ? 'csrf' : 'cross-origin' },
      outcome: 'failure',
    });
  }

  redirect(`/${await getLocale()}/login`);
}

export interface ChangePasswordState {
  readonly errors?: FieldErrors;
  readonly message?: string;
  readonly success?: boolean;
}

export async function changePassword(
  _prev: ChangePasswordState,
  formData: FormData,
): Promise<ChangePasswordState> {
  if (!(await isSameOrigin())) {
    return { message: 'This request could not be verified. Please reload and retry.' };
  }

  const active = await session.current();
  if (!active) redirect(`/${await getLocale()}/login`);

  const submitted = formData.get(CSRF_FIELD);
  if (!(await verifyCsrf(typeof submitted === 'string' ? submitted : null, active.sessionId))) {
    return { message: 'This request could not be verified. Please reload and retry.' };
  }

  const limited = rateLimit.consume('mutation', active.sessionId);
  if (!limited.allowed) {
    return { message: 'Too many requests. Please wait a moment and try again.' };
  }

  const currentPassword = String(formData.get('currentPassword') ?? '');
  const newPassword = String(formData.get('newPassword') ?? '');
  const confirmPassword = String(formData.get('confirmPassword') ?? '');

  const errors: FieldErrors = {};

  const validCurrent = await verifyPassword(currentPassword, active.user.passwordHash);
  if (!validCurrent) {
    errors.currentPassword = ['Current password is incorrect.'];
  }

  const policy = passwordSchema.safeParse(newPassword);
  if (!policy.success) {
    errors.newPassword = policy.error.issues.map((i) => i.message);
  }

  if (newPassword !== confirmPassword) {
    errors.confirmPassword = ['The two passwords do not match.'];
  }

  if (Object.keys(errors).length > 0) {
    return { errors };
  }

  const passwordHash = await hashPassword(newPassword);
  setPassword(active.user.id, passwordHash);

  const ctx = await context();
  audit.record({
    action: 'auth.password.changed',
    actorUserId: active.user.id,
    actorEmail: active.user.email,
    ip: ctx.ip,
  });

  // Rotate the session and revoke every other one: a password change must
  // invalidate any token an attacker captured under the old credential.
  session.revokeAllForUser(active.user.id);
  await session.create(active.user.id, ctx);

  return { success: true };
}
