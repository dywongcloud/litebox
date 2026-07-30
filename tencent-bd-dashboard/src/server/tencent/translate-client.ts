import 'server-only';

import { z } from 'zod';

import { env } from '@/lib/env';

import { callTencentApi, type TencentApiResult } from './signer';

/**
 * Client for the Tencent Cloud Machine Translation `TextTranslate` action.
 *
 * https://www.tencentcloud.com/document/product/551/15619
 *
 * `Source`/`Target` are two-letter language codes (`en`, `zh`), not the app's
 * `Locale` type -- TMT has no concept of Simplified vs Traditional as a
 * translation target, only as a property of the `zh` text it returns. Script
 * variant handling is therefore layered on top by the translation service
 * (`@/server/translation/service`), not here.
 */

const textTranslateResponseSchema = z.object({
  TargetText: z.string(),
  Source: z.string(),
  Target: z.string(),
});

export interface TranslateResult {
  readonly text: string;
}

export async function translateText(
  text: string,
  source: 'en' | 'zh',
  target: 'en' | 'zh',
): Promise<TencentApiResult<TranslateResult>> {
  const result = await callTencentApi<unknown>({
    service: 'tmt',
    host: 'tmt.tencentcloudapi.com',
    action: 'TextTranslate',
    version: '2018-03-21',
    region: env.TENCENTCLOUD_REGION,
    payload: {
      SourceText: text,
      Source: source,
      Target: target,
      ProjectId: env.TENCENTCLOUD_TMT_PROJECT_ID,
    },
  });

  if (!result.ok) return result;

  const parsed = textTranslateResponseSchema.safeParse(result.data);
  if (!parsed.success) {
    return {
      ok: false,
      code: 'Client.UnexpectedShape',
      message: `Upstream response did not match the expected schema: ${parsed.error.message}`,
    };
  }

  return { ok: true, data: { text: parsed.data.TargetText }, requestId: '' };
}
