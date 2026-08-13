import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The bar and its controls are built from library components.
 *
 * The first version of this guard listed allowed MUI *modules*, which let a new
 * MUI symbol slip in under a module that was already allowed — `Stack` arrived
 * that way under `@mui/material`. So the unit here is the SYMBOL: every name
 * imported from MUI, in the bar and in the components the bar owns, must appear
 * in `ALLOWED` below, with the reason it is still there and what would retire
 * it. A new symbol from an already-allowed module fails.
 */

const FILES = [
  'src/private/components/nav/TopBar.tsx',
  'src/private/components/nav/TopBarIconLink.tsx',
  'src/private/components/chatbox/AskArianeButton.tsx',
  'src/private/components/chatbox/CtemCommandCenterButton.tsx',
  'src/components/UploadImport.tsx',
];

const read = (f: string) => readFileSync(path.resolve(f), 'utf8');
const SOURCES = new Map(FILES.map((f) => [f, read(f)]));

/**
 * MUI symbols the bar may still import, and the condition that retires each.
 * Nothing else is allowed — not even from a module already named here.
 */
const ALLOWED: Record<string, string> = {
  // Retired by: a library icon set covering the bar's glyphs.
  AccountCircleOutlined: 'glyph',
  AlarmOnOutlined: 'glyph',
  NotificationsOutlined: 'glyph',
  FileUploadOutlined: 'glyph',
  RadarOutlined: 'glyph',
  // Retired by: the product dropping the legacy MUI theme. The bar reads the
  // palette to build its own gradient; it renders nothing with it.
  useTheme: 'palette read, renders nothing',
  makeStyles: 'paints the Suspense fallback only',
  // Retired by: a library Header skeleton. The fallback keeps `background.nav`
  // unchanged by arbitration, and is not the rendered bar.
  AppBar: 'Suspense fallback only',
};

/** Component families the rendered bar must no longer contain. */
const RETIRED = ['MuiBadge-', 'MuiStack-', 'CircularProgress'];

/** Named survivors: MUI still rendered, with the gap that keeps them alive. */
const SURVIVORS = [
  {
    symbol: 'ToggleButtonGroup',
    file: 'src/components/SearchInput.jsx',
    retiredBy: 'LIBRARY-FEEDBACK #24 — the library ships no segmented control',
  },
  {
    symbol: 'ToggleButton',
    file: 'src/components/SearchInput.jsx',
    retiredBy: 'LIBRARY-FEEDBACK #24 — the library ships no segmented control',
  },
];

const importedSymbols = (source: string) => {
  const symbols: string[] = [];
  const re = /^import\s+([^;]*?)\s+from\s+'(@mui\/[^']+)';/gms;
  for (const [, clause, module] of source.matchAll(re)) {
    const braced = /\{([^}]*)\}/s.exec(clause);
    if (braced) {
      symbols.push(...braced[1].split(',').map((s) => s.trim().split(/\s+as\s+/)[0]).filter(Boolean));
    }
    const defaultName = clause.replace(/\{[^}]*\}/s, '').replace(/,/g, '').trim();
    if (defaultName) symbols.push(defaultName);
    // `import makeStyles from '@mui/styles/makeStyles'` names the symbol in the
    // path, not the clause — count the path's tail too, so the module cannot be
    // used as a back door.
    const tail = module.split('/').pop();
    if (tail && /^[a-z]/i.test(tail) && tail !== 'material' && tail !== 'styles' && tail !== 'icons-material') {
      symbols.push(tail);
    }
  }
  return symbols;
};

describe('the admin top bar is built from library components', () => {
  it.each(FILES)('%s imports no MUI symbol outside the allow-list', (file) => {
    for (const symbol of importedSymbols(SOURCES.get(file) as string)) {
      // The message names the symbol, so a failure says what arrived rather
      // than only that a count changed.
      expect(ALLOWED, `${symbol} is imported by ${file} and is not an allowed MUI symbol`)
        .toHaveProperty(symbol);
    }
  });

  it.each(RETIRED)('the bar no longer renders %s', (family) => {
    for (const source of SOURCES.values()) expect(source).not.toContain(family);
  });

  it.each(SURVIVORS)('$symbol survives only while $retiredBy', ({ symbol, file }) => {
    // A survivor that disappears should delete its entry here, not leave a
    // stale licence behind.
    expect(read(file)).toContain(symbol);
  });

  it('takes the bar controls from the library', () => {
    const bar = SOURCES.get('src/private/components/nav/TopBar.tsx') as string;
    for (const symbol of ['Header', 'HeaderGroup', 'Badge', 'IconButton', 'Menu']) {
      expect(bar).toMatch(new RegExp(`import \\{[^}]*\\b${symbol}\\b[^}]*\\} from '@filigran/design-system'`, 's'));
    }
  });

  it('draws the cluster rule with the library separator, never a styled div', () => {
    const bar = SOURCES.get('src/private/components/nav/TopBar.tsx') as string;
    expect(bar).toMatch(/<HeaderGroup separatorBefore=/);
    expect(bar).not.toMatch(/role="separator"/);
  });

  it('takes the AI controls from the library in their ia variant', () => {
    const ariane = SOURCES.get('src/private/components/chatbox/AskArianeButton.tsx') as string;
    expect(ariane).toMatch(/from '@filigran\/design-system'/);
    expect(ariane).toMatch(/variant="ia"/);
    const ctem = SOURCES.get('src/private/components/chatbox/CtemCommandCenterButton.tsx') as string;
    expect(ctem).toMatch(/variant="ia"/);
  });

  it('no longer builds the rendered bar from AppBar or Toolbar', () => {
    const bar = SOURCES.get('src/private/components/nav/TopBar.tsx') as string;
    expect(bar).not.toMatch(/<Toolbar\b/);
    expect([...bar.matchAll(/<AppBar\b/g)]).toHaveLength(1);
    expect(bar).toMatch(/fallback=\{\(\s*<AppBar/s);
  });

  it('keeps the gradient off :root, so only this bar is repainted', () => {
    const bar = SOURCES.get('src/private/components/nav/TopBar.tsx') as string;
    expect(bar).toMatch(/'--gradient-default':/);
    expect(bar).not.toMatch(/:root/);
  });

  it('states the search window through the named constants', () => {
    const bar = SOURCES.get('src/private/components/nav/TopBar.tsx') as string;
    expect(bar).toMatch(/minWidth: TOP_BAR_SEARCH_MIN_WIDTH/);
    expect(bar).toMatch(/maxWidth: TOP_BAR_SEARCH_MAX_WIDTH/);
  });
});
