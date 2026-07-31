/**
 * Minimal RFC 4180 CSV writer.
 *
 * Values are quoted whenever they contain the delimiter, a quote, or a line
 * break, with embedded quotes doubled -- the same rule spreadsheet apps
 * expect, so exported files open cleanly in Excel/Sheets/Numbers without a
 * dependency for what is a handful of string rules.
 */
function escapeCell(value: unknown): string {
  const text = value === null || value === undefined ? '' : String(value);
  if (/["\n\r,]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

export function toCsv(headers: readonly string[], rows: ReadonlyArray<ReadonlyArray<unknown>>): string {
  const lines = [headers.map(escapeCell).join(',')];
  for (const row of rows) {
    lines.push(row.map(escapeCell).join(','));
  }
  // CRLF is the RFC 4180 line ending and what Excel expects on every platform.
  return lines.join('\r\n') + '\r\n';
}
