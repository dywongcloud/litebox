import 'server-only';

import { z } from 'zod';

import { env } from '@/lib/env';

import { callTencentApi, type TencentApiResult } from './signer';

/**
 * Client for the Tencent Cloud Billing `DescribeProducts` action.
 *
 * https://www.tencentcloud.com/document/api/555/34992 -- returns the catalog of
 * billable product and sub-product codes used for cost allocation. It is the
 * one stable, documented, generally-available Tencent Cloud API that returns a
 * product code/name catalog; there is no public "marketing catalog" API, so
 * this is what "consume upstream Tencent Cloud Product APIs" resolves to for a
 * BD tool that needs canonical product identifiers rather than page copy.
 *
 * The response only carries codes and names -- everything else in a product row
 * (competitors, pain points, BD motion, evidence) is intelligence this tool
 * exists to capture and stays purely local. A sync therefore only ever creates
 * a stub row or attaches an upstream code to an existing one; it never
 * overwrites the fields a BD rep has written.
 */

const rawItemSchema = z.object({
  BusinessCode: z.string(),
  BusinessName: z.string(),
  ProductCode: z.string().optional(),
  ProductName: z.string().optional(),
});

const describeProductsResponseSchema = z.object({
  Total: z.number().optional(),
  ProductInfos: z.array(rawItemSchema).optional(),
  // Some API versions nest one level deeper; accept both shapes defensively
  // rather than throwing on a field Tencent Cloud is free to add or rename.
  BusinessSet: z.array(rawItemSchema).optional(),
});

export interface UpstreamCatalogItem {
  readonly code: string;
  readonly name: string;
}

const PAGE_SIZE = 100;
/** Absolute cap on pages fetched, independent of what `Total` claims. */
const MAX_PAGES = 20;

/**
 * Fetch the full upstream product catalog, paginating until the API reports no
 * more items or `MAX_PAGES` is reached.
 *
 * Every page is validated with Zod before use: this is the one place the
 * application trusts a byte over the network for something that ends up in
 * the product table, so a malformed or unexpected shape must fail closed
 * rather than write garbage.
 */
export async function fetchUpstreamCatalog(): Promise<TencentApiResult<UpstreamCatalogItem[]>> {
  const items: UpstreamCatalogItem[] = [];
  let offset = 0;

  for (let page = 0; page < MAX_PAGES; page++) {
    const result = await callTencentApi<unknown>({
      service: 'billing',
      host: 'billing.tencentcloudapi.com',
      action: 'DescribeProducts',
      version: '2018-07-09',
      region: env.TENCENTCLOUD_REGION,
      payload: { Offset: offset, Limit: PAGE_SIZE },
    });

    if (!result.ok) return result;

    const parsed = describeProductsResponseSchema.safeParse(result.data);
    if (!parsed.success) {
      return {
        ok: false,
        code: 'Client.UnexpectedShape',
        message: `Upstream response did not match the expected schema: ${parsed.error.message}`,
      };
    }

    const rawItems = parsed.data.ProductInfos ?? parsed.data.BusinessSet ?? [];
    for (const raw of rawItems) {
      const code = raw.ProductCode ?? raw.BusinessCode;
      const name = raw.ProductName ?? raw.BusinessName;
      if (code && name) items.push({ code, name });
    }

    const total = parsed.data.Total ?? items.length;
    offset += PAGE_SIZE;
    if (rawItems.length === 0 || offset >= total) break;
  }

  return { ok: true, data: items, requestId: '' };
}
