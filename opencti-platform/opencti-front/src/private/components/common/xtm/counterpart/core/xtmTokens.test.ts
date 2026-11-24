/**
 * Every design token the XTM counterpart components paint with must be one the
 * design system defines: an undefined custom property resolves to nothing, so a
 * divider vanishes and a secondary label takes the primary ink (UX round 10, B1).
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { FDS } from '../../../../../../components/fds-tokens.generated';

const root = path.join(__dirname, '..');

const sourcesOf = (dir: string): string[] => fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
  const full = path.join(dir, entry.name);
  if (entry.isDirectory()) return entry.name === '__generated__' ? [] : sourcesOf(full);
  return /\.(tsx?|jsx?)$/.test(entry.name) && !/\.test\./.test(entry.name) ? [full] : [];
});

const defined = (mode: 'dark' | 'light'): Set<string> => new Set([
  ...Object.keys(FDS.colors[mode]),
  ...Object.keys(FDS.gradients[mode]),
  ...Object.keys(FDS.scalars),
]);

describe('XTM counterpart design tokens', () => {
  const used = sourcesOf(root).flatMap((file) => [...fs.readFileSync(file, 'utf8').matchAll(/var\((--[\w-]+)\)/g)]
    .map(([, token]) => ({ file: path.relative(root, file), token })));

  it('paints with tokens at all', () => {
    expect(used.length).toBeGreaterThan(0);
  });

  it.each(['dark', 'light'] as const)('uses only tokens the design system defines (%s)', (mode) => {
    const known = defined(mode);
    expect(used.filter(({ token }) => !known.has(token))).toEqual([]);
  });
});
