import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// Every literal the intelligence requirement screens pass to t_i18n exists in every front catalog,
// so no sentence of the module reaches a reader in English because its key is missing.

const moduleDir = dirname(fileURLToPath(import.meta.url));
const langDir = resolve(moduleDir, '../../../../lang/front');

const sources = (dir: string): string[] => readdirSync(dir).flatMap((name) => {
  const full = join(dir, name);
  if (statSync(full).isDirectory()) return name === '__generated__' ? [] : sources(full);
  return /\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name) ? [full] : [];
});

const literalKeys = () => {
  const keys = new Map<string, string>();
  const pattern = /t_i18n\(\s*'((?:[^'\\]|\\.)*)'/g;
  sources(moduleDir).forEach((file) => {
    const text = readFileSync(file, 'utf8');
    for (const match of text.matchAll(pattern)) {
      keys.set(match[1].replace(/\\'/g, "'"), file.slice(moduleDir.length + 1));
    }
  });
  return keys;
};

describe('intelligence requirement catalogs', () => {
  const keys = literalKeys();
  const catalogs = readdirSync(langDir).filter((name) => name.endsWith('.json'));

  it('reads the module keys and the catalogs', () => {
    expect(keys.size).toBeGreaterThan(100);
    expect(catalogs).toContain('fr.json');
  });

  it.each(catalogs)('%s holds every literal key of the module', (catalog) => {
    const entries = JSON.parse(readFileSync(join(langDir, catalog), 'utf8')) as Record<string, string>;
    const missing = [...keys.entries()].filter(([key]) => !(key in entries)).map(([key, file]) => `${file}: ${key}`);
    expect(missing).toEqual([]);
  });
});
