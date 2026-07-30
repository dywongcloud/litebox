/**
 * Generate `src/i18n/messages/zh-Hant.json` from the Simplified catalog.
 *
 * The Traditional catalog is derived, never hand-maintained: keeping two
 * Chinese catalogs in sync by hand guarantees they drift, and the difference
 * between them is a mechanical script conversion, not a translation.
 *
 * Conversion is `cn -> tw` (character level). The `twp` variant additionally
 * substitutes Taiwan vocabulary, which changes word choice rather than script;
 * that is a translation decision and is deliberately left to a human reviewer.
 *
 * Run: npx tsx scripts/generate-zh-hant.ts
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as OpenCC from 'opencc-js';

const here = dirname(fileURLToPath(import.meta.url));
const messagesDir = resolve(here, '../src/i18n/messages');

const convert = OpenCC.Converter({ from: 'cn', to: 'tw' });

type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

/**
 * Walk the catalog, converting only string leaves.
 *
 * Keys are ASCII identifiers referenced from code and must survive untouched --
 * converting a key would silently break every lookup that uses it.
 */
function convertTree(value: Json): Json {
  if (typeof value === 'string') return convert(value);
  if (Array.isArray(value)) return value.map(convertTree);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, convertTree(v)]));
  }
  return value;
}

const sourcePath = resolve(messagesDir, 'zh-Hans.json');
const targetPath = resolve(messagesDir, 'zh-Hant.json');

const source = JSON.parse(readFileSync(sourcePath, 'utf8')) as Json;
const converted = convertTree(source);

writeFileSync(targetPath, `${JSON.stringify(converted, null, 2)}\n`, 'utf8');

function countLeaves(value: Json): number {
  if (typeof value === 'string') return 1;
  if (Array.isArray(value)) return value.reduce<number>((n, v) => n + countLeaves(v), 0);
  if (value !== null && typeof value === 'object') {
    return Object.values(value).reduce<number>((n, v) => n + countLeaves(v), 0);
  }
  return 0;
}

console.log(`Wrote ${targetPath} (${countLeaves(converted)} strings converted cn -> tw)`);
