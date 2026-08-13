import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The bar is built from library components. Enumerating that by eye is what let
 * MUI survivors accumulate in the first place, so the enumeration lives here:
 * every MUI import in the bar must be one of the survivors named below, each of
 * which has an open entry in fds-migration/LIBRARY-FEEDBACK.md.
 */

const TOP_BAR = readFileSync(path.resolve('src/private/components/nav/TopBar.tsx'), 'utf8');

/** MUI imports the bar is still allowed to carry, and why. */
const ALLOWED_MUI = [
  '@mui/icons-material', // glyphs only — the library ships no icon set
  '@mui/styles', // useTheme, for the product's own palette
  '@mui/material/AppBar', // Suspense fallback only, asserted below
  '@mui/styles/makeStyles', // paints that same fallback from background.nav
];

/** Component families the bar must not render. Each was retired to the library. */
const RETIRED_MUI = ['MuiBadge-'];

const muiImports = [...TOP_BAR.matchAll(/^import[^;]*?from '(@mui\/[^']+)';/gms)]
  .map((m) => m[1]);

describe('the admin top bar is built from library components', () => {
  it.each(RETIRED_MUI)('no longer renders %s', (family) => {
    expect(TOP_BAR).not.toContain(family);
  });

  it('takes its Badge from the library', () => {
    expect(TOP_BAR).toMatch(/import \{[^}]*\bBadge\b[^}]*\} from '@filigran\/design-system'/s);
  });

  it('imports the library Header and its group', () => {
    expect(TOP_BAR).toMatch(/import \{[^}]*\bHeader\b[^}]*\} from '@filigran\/design-system'/s);
    expect(TOP_BAR).toMatch(/import \{[^}]*\bHeaderGroup\b[^}]*\} from '@filigran\/design-system'/s);
  });

  it('carries no MUI import beyond the named survivors', () => {
    expect(muiImports.length).toBeGreaterThan(0);
    for (const source of muiImports) {
      expect(ALLOWED_MUI).toContain(source);
    }
  });

  it('no longer builds the rendered bar from AppBar or Toolbar', () => {
    expect(TOP_BAR).not.toMatch(/<Toolbar\b/);
    expect(TOP_BAR).not.toMatch(/import Toolbar from/);
    // AppBar survives in exactly one place: the Suspense fallback, whose
    // `background.nav` paint this pilot preserves unchanged (arbitration).
    expect([...TOP_BAR.matchAll(/<AppBar\b/g)]).toHaveLength(1);
    expect(TOP_BAR).toMatch(/fallback=\{\(\s*<AppBar/s);
  });

  it('keeps the gradient off :root, so only this bar is repainted', () => {
    expect(TOP_BAR).toMatch(/'--gradient-default':/);
    expect(TOP_BAR).not.toMatch(/:root/);
  });

  it('states the search window through the named constants', () => {
    expect(TOP_BAR).toMatch(/minWidth: TOP_BAR_SEARCH_MIN_WIDTH/);
    expect(TOP_BAR).toMatch(/maxWidth: TOP_BAR_SEARCH_MAX_WIDTH/);
  });
});
