import 'server-only';

import {
  createHash,
  createHmac,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
} from 'node:crypto';
import { promisify } from 'node:util';

import { env } from '@/lib/env';

const scrypt = promisify(scryptCallback) as (
  password: string | Buffer,
  salt: string | Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>;

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/**
 * Derive a purpose-scoped key from `APP_SECRET`.
 *
 * Distinct purposes yield unrelated keys, so a CSRF token can never be replayed
 * as a session token even though both are HMACs over the same root secret.
 */
function derivedKey(purpose: string): Buffer {
  return createHmac('sha256', env.APP_SECRET).update(`bd-os:v1:${purpose}`).digest();
}

const SESSION_KEY = derivedKey('session');
const CSRF_KEY = derivedKey('csrf');
const PSEUDONYM_KEY = derivedKey('pseudonym');

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/** URL-safe random token. 32 bytes is 256 bits of entropy. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/**
 * Constant-time string comparison.
 *
 * Hashes both inputs first so operands are always the same length: comparing
 * raw strings of differing length leaks the length through the early return
 * inside `timingSafeEqual`.
 */
export function safeEqual(a: string, b: string): boolean {
  const bufA = createHash('sha256').update(a, 'utf8').digest();
  const bufB = createHash('sha256').update(b, 'utf8').digest();
  return timingSafeEqual(bufA, bufB);
}

/** Keyed digest of a session token, for the value stored at rest. */
export function hashSessionToken(token: string): string {
  return createHmac('sha256', SESSION_KEY).update(token, 'utf8').digest('hex');
}

/** Keyed digest binding a CSRF token to its session. */
export function signCsrf(sessionId: string, nonce: string): string {
  return createHmac('sha256', CSRF_KEY).update(`${sessionId}.${nonce}`, 'utf8').digest('base64url');
}

/**
 * Irreversible, stable pseudonym for an IP address, user agent, or email.
 *
 * Rate limiting and audit correlation need a stable identifier for a subject;
 * they do not need the subject itself. Keying the digest stops an attacker who
 * reads the database from recovering the IP by hashing candidates, which a
 * plain SHA-256 of a 32-bit address would allow trivially.
 */
export function pseudonymise(value: string): string {
  if (!value) return '';
  return createHmac('sha256', PSEUDONYM_KEY).update(value, 'utf8').digest('hex').slice(0, 32);
}

// ---------------------------------------------------------------------------
// Password hashing
// ---------------------------------------------------------------------------

/**
 * scrypt parameters. N=2^16 with r=8 costs roughly 64 MiB and ~100 ms per hash
 * on current server hardware -- expensive enough to make offline cracking of a
 * stolen hash costly, cheap enough that a sign-in stays interactive.
 */
const SCRYPT_N = 65_536;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 64;
const SCRYPT_MAXMEM = 192 * 1024 * 1024;

/**
 * Hash a password to a self-describing string:
 *   `scrypt$N$r$p$<salt base64url>$<hash base64url>`
 *
 * Embedding the cost parameters means they can be raised later without
 * invalidating existing credentials -- `verifyPassword` reads whatever
 * parameters a given hash was created with.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const hash = await scrypt(password.normalize('NFKC'), salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });

  return [
    'scrypt',
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
    salt.toString('base64url'),
    hash.toString('base64url'),
  ].join('$');
}

/**
 * Verify a password against a stored hash.
 *
 * Returns false rather than throwing on a malformed hash: a corrupt row must
 * deny access, not surface a 500 that distinguishes it from a wrong password.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const [, rawN, rawR, rawP, rawSalt, rawHash] = parts;
  const N = Number(rawN);
  const r = Number(rawR);
  const p = Number(rawP);

  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) return false;
  // Guard against a tampered row demanding an unbounded amount of memory.
  if (N < 1024 || N > 1_048_576 || r < 1 || r > 32 || p < 1 || p > 16) return false;
  if (!rawSalt || !rawHash) return false;

  const expected = Buffer.from(rawHash, 'base64url');
  if (expected.length === 0) return false;

  try {
    const actual = await scrypt(
      password.normalize('NFKC'),
      Buffer.from(rawSalt, 'base64url'),
      expected.length,
      { N, r, p, maxmem: SCRYPT_MAXMEM },
    );
    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

/**
 * Burn roughly the cost of a real verification.
 *
 * Called when no user matches the submitted email, so the response time of an
 * unknown address is indistinguishable from a known one with a wrong password.
 * Without this, sign-in latency is a user-enumeration oracle.
 */
export async function dummyVerify(): Promise<void> {
  await scrypt('bd-os-timing-equaliser', randomBytes(16), SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });
}
