import 'server-only';

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

import * as audit from '@/lib/security/audit';
import * as rateLimit from '@/lib/security/rate-limit';
import { clientIp } from '@/lib/security/request';

/**
 * CSP violation reports.
 *
 * The browser POSTs here on its own -- there is no session, no CSRF token,
 * and no user gesture behind the request, so this deliberately skips
 * `requireMutation`'s origin/CSRF checks (they would reject every legitimate
 * report). What stands in for that gate is: the endpoint only ever writes an
 * audit entry, never touches business data, and is rate-limited per IP so a
 * scripted flood cannot use it to bloat the audit table.
 *
 * Accepts both the legacy `report-uri` shape (`application/csp-report`, one
 * report per request), and the newer `report-to` Reporting API shape
 * (`application/reports+json`, a batch array) -- browsers are migrating
 * between the two on their own schedule, not ours.
 */

interface NormalisedReport {
  documentUri: string;
  violatedDirective: string;
  blockedUri: string;
  disposition: string;
}

function normaliseLegacy(body: unknown): NormalisedReport | null {
  if (typeof body !== 'object' || body === null || !('csp-report' in body)) return null;
  const report = (body as { 'csp-report': unknown })['csp-report'];
  if (typeof report !== 'object' || report === null) return null;
  const r = report as Record<string, unknown>;
  return {
    documentUri: typeof r['document-uri'] === 'string' ? r['document-uri'] : '',
    violatedDirective: typeof r['violated-directive'] === 'string' ? r['violated-directive'] : '',
    blockedUri: typeof r['blocked-uri'] === 'string' ? r['blocked-uri'] : '',
    disposition: typeof r['disposition'] === 'string' ? r['disposition'] : '',
  };
}

function normaliseReportingApi(body: unknown): NormalisedReport[] {
  if (!Array.isArray(body)) return [];
  const out: NormalisedReport[] = [];
  for (const entry of body) {
    if (typeof entry !== 'object' || entry === null) continue;
    const e = entry as Record<string, unknown>;
    if (e.type !== 'csp-violation') continue;
    const b = e.body;
    if (typeof b !== 'object' || b === null) continue;
    const r = b as Record<string, unknown>;
    out.push({
      documentUri: typeof r.documentURL === 'string' ? r.documentURL : '',
      violatedDirective: typeof r.effectiveDirective === 'string' ? r.effectiveDirective : '',
      blockedUri: typeof r.blockedURL === 'string' ? r.blockedURL : '',
      disposition: typeof r.disposition === 'string' ? r.disposition : '',
    });
  }
  return out;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const ip = await clientIp();
  const limited = rateLimit.consume('csp-report', ip);
  if (!limited.allowed) {
    return new NextResponse(null, { status: 204 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return new NextResponse(null, { status: 204 });
  }

  const reports = normaliseReportingApi(body);
  const legacy = normaliseLegacy(body);
  if (legacy) reports.push(legacy);

  for (const report of reports.slice(0, 20)) {
    audit.record({
      action: 'security.csp-violation',
      entityType: 'csp',
      ip,
      metadata: {
        documentUri: report.documentUri,
        violatedDirective: report.violatedDirective,
        blockedUri: report.blockedUri,
        disposition: report.disposition,
      },
    });
  }

  // Reports never get a body back; 204 either way avoids leaking whether the
  // rate limit or the parse is what short-circuited a given request.
  return new NextResponse(null, { status: 204 });
}
