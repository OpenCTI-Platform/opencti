/**
 * Every `var(--token)` the investigation matrix and the shared attack-pattern matrix use must be
 * defined by the design-system stylesheet the app loads (`src/front.tsx`). A token that exists in
 * the library's `theme.css` but is not compiled into `dist/index.css` resolves to nothing at
 * runtime: a fill goes transparent and a label colour falls back to the inherited one
 * (LIBRARY-FEEDBACK.md #70).
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';

const require = createRequire(import.meta.url);
const DESIGN_SYSTEM_CSS = require.resolve('@filigran/design-system/dist/index.css');

const SCANNED_DIRS = [
  __dirname,
  path.join(__dirname, '../../../techniques/attack_patterns/attack_patterns_matrix'),
];

const sourceFiles = SCANNED_DIRS.flatMap((dir) => fs.readdirSync(dir)
  .filter((name) => /\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name))
  .map((name) => path.join(dir, name)));

const usedTokens = (source: string) => Array.from(source.matchAll(/var\((--[\w-]+)/g), (match) => match[1]);

const escape = (token: string) => token.replace(/[-]/g, '\\-');

const isDefined = (css: string, token: string) => new RegExp(`(?<![\\w-])${escape(token)}\\s*:`).test(css);

describe('matrix colour tokens', () => {
  const css = fs.readFileSync(DESIGN_SYSTEM_CSS, 'utf8');

  it('scans the matrix sources', () => {
    const names = sourceFiles.map((file) => path.basename(file));
    expect(names).toEqual(expect.arrayContaining([
      'heatScale.ts',
      'buildCellDecorations.ts',
      'HeatmapLegend.tsx',
      'attackPatternsMatrixConfig.ts',
      'AttackPatternsMatrixColumns.tsx',
    ]));
  });

  it.each(sourceFiles.map((file) => [path.relative(path.join(__dirname, '../../../../..'), file), file]))(
    '%s uses only tokens defined in @filigran/design-system/dist/index.css',
    (_name, file) => {
      const undefinedTokens = usedTokens(fs.readFileSync(file, 'utf8')).filter((token) => !isDefined(css, token));
      expect(undefinedTokens).toEqual([]);
    },
  );
});
