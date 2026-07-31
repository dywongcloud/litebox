import 'server-only';

import { createHash, createHmac } from 'node:crypto';

import { env } from '@/lib/env';

/**
 * Tencent Cloud API v3 (TC3-HMAC-SHA256) request signing.
 *
 * Implements the algorithm documented at
 * https://www.tencentcloud.com/document/product/1278/48705 (Signature v3).
 * Every upstream Tencent Cloud call in this app (product catalog, machine
 * translation) goes through this one function so the signing logic exists in
 * exactly one place.
 *
 * The secret key never leaves the process: it is read from `env` (server-only,
 * never sent to the client) and used only to compute local HMACs. Nothing here
 * transmits `TENCENTCLOUD_SECRET_KEY` itself.
 */

export interface TencentApiRequest {
  readonly service: string;
  readonly host: string;
  readonly action: string;
  readonly version: string;
  readonly region?: string;
  readonly payload: Record<string, unknown>;
  /** Request timeout, in ms. Bounded so a hung upstream cannot wedge a request. */
  readonly timeoutMs?: number;
}

export interface TencentApiSuccess<T> {
  readonly ok: true;
  readonly data: T;
  readonly requestId: string;
}

export interface TencentApiFailure {
  readonly ok: false;
  /** Machine-readable code, e.g. `AuthFailure.SecretIdNotFound`. Never the raw body. */
  readonly code: string;
  readonly message: string;
}

export type TencentApiResult<T> = TencentApiSuccess<T> | TencentApiFailure;

function sha256Hex(payload: string): string {
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

function hmacSha256(key: Buffer | string, payload: string): Buffer {
  return createHmac('sha256', key).update(payload, 'utf8').digest();
}

/**
 * Sign and send one Tencent Cloud API v3 request.
 *
 * Returns a discriminated result rather than throwing on an API-level error:
 * an upstream credential or quota failure is an expected, handleable outcome
 * for a BD tool whose core function must keep working without it (see
 * `hasTencentCredentials` call sites), not an exceptional one.
 */
export async function callTencentApi<T>(request: TencentApiRequest): Promise<TencentApiResult<T>> {
  const secretId = env.TENCENTCLOUD_SECRET_ID;
  const secretKey = env.TENCENTCLOUD_SECRET_KEY;

  if (!secretId || !secretKey) {
    return { ok: false, code: 'Client.NotConfigured', message: 'Tencent Cloud credentials are not configured' };
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const date = new Date(timestamp * 1000).toISOString().slice(0, 10);

  const body = JSON.stringify(request.payload);

  // --- Step 1: canonical request ---------------------------------------------
  const canonicalHeaders = `content-type:application/json; charset=utf-8\nhost:${request.host}\nx-tc-action:${request.action.toLowerCase()}\n`;
  const signedHeaders = 'content-type;host;x-tc-action';

  const canonicalRequest = [
    'POST',
    '/',
    '',
    canonicalHeaders,
    signedHeaders,
    sha256Hex(body),
  ].join('\n');

  // --- Step 2: string to sign --------------------------------------------------
  const credentialScope = `${date}/${request.service}/tc3_request`;
  const stringToSign = [
    'TC3-HMAC-SHA256',
    String(timestamp),
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  // --- Step 3: derive the signing key and sign ---------------------------------
  const secretDate = hmacSha256(`TC3${secretKey}`, date);
  const secretService = hmacSha256(secretDate, request.service);
  const secretSigning = hmacSha256(secretService, 'tc3_request');
  const signature = hmacSha256(secretSigning, stringToSign).toString('hex');

  const authorization = `TC3-HMAC-SHA256 Credential=${secretId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const headers: Record<string, string> = {
    Authorization: authorization,
    'Content-Type': 'application/json; charset=utf-8',
    Host: request.host,
    'X-TC-Action': request.action,
    'X-TC-Timestamp': String(timestamp),
    'X-TC-Version': request.version,
  };
  if (request.region) headers['X-TC-Region'] = request.region;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), request.timeoutMs ?? 10_000);

  try {
    const response = await fetch(`https://${request.host}/`, {
      method: 'POST',
      headers,
      body,
      signal: controller.signal,
    });

    const json = (await response.json()) as {
      Response?: {
        Error?: { Code: string; Message: string };
        RequestId?: string;
        [key: string]: unknown;
      };
    };

    const inner = json.Response;
    if (!inner) {
      return { ok: false, code: 'Client.MalformedResponse', message: 'Upstream returned an unexpected shape' };
    }

    if (inner.Error) {
      return { ok: false, code: inner.Error.Code, message: inner.Error.Message };
    }

    return { ok: true, data: inner as T, requestId: inner.RequestId ?? '' };
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      return { ok: false, code: 'Client.Timeout', message: 'Request to Tencent Cloud timed out' };
    }
    return {
      ok: false,
      code: 'Client.NetworkError',
      message: error instanceof Error ? error.message : 'Unknown network error',
    };
  } finally {
    clearTimeout(timeout);
  }
}
