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

/**
 * The search field carries the two exempted gaps, so its allow-list is the one
 * below plus `EXEMPTED`. It is checked by symbol all the same: the exemption
 * covers named components, not the file.
 */
const SEARCH_FIELD = 'src/components/SearchInput.jsx';

const read = (f: string) => readFileSync(path.resolve(f), 'utf8');
const SOURCES = new Map([...FILES, SEARCH_FIELD].map((f) => [f, read(f)]));

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
  ManageSearchOutlined: 'glyph',
  Search: 'glyph',
  TuneOutlined: 'glyph',
  KeyboardArrowDownOutlined: 'glyph',
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

/**
 * The two exemptions Sandy granted on 2026-08-13, and nothing else. Each names
 * the component the library owes and the single condition that retires the
 * whole row — so an exemption cannot quietly become a habit.
 */
const EXEMPTED: Record<string, string> = {
  // Segmented control — LIBRARY-FEEDBACK #24. All of these go together the day
  // the library ships one.
  ToggleButtonGroup: '#24 segmented control',
  ToggleButton: '#24 segmented control',
  // MUI's group injects `value`/`selected` into its children THROUGH the
  // tooltip (measured: `data-mui-internal-clone-element` on the wrapper, and
  // `Mui-selected` arriving on the toggle). A library Tooltip is not in that
  // cloning contract, so swapping it silently breaks selection — the tooltip
  // is part of the segmented control, not a separate choice.
  Tooltip: '#24 inside the segmented control cloning contract',
  // The agent dropdown hangs off the caret inside a `ToggleButton`; a Radix
  // trigger would have to nest a button inside a button.
  Menu: '#24 blocked by the same missing segmented control',
  MenuItem: '#24 blocked by the same missing segmented control',
  ListItemIcon: '#24 rows of that same menu',
  ListItemText: '#24 rows of that same menu',
  // Popover — the second exemption. It is not imported here: it arrives as
  // MUI's own implementation of the exempted menu (`MenuRoot = styled(Popover)`
  // in @mui/material), and the library exports no public Popover at pin
  // 35a4768 — verified on the installed build, not assumed. Declared by name so
  // that importing one directly is still a named, dated exemption.
  Popover: '#24 MUI draws the exempted menu with it; no library Popover yet',
  // Not the bar: `GradientBorderTextField` serves the drawer and page variants
  // of this same component. The bar's own field is the library `SearchField`.
  TextField: 'non-topBar variants only, never rendered in the bar',
};

/**
 * Declared but not imported today. `Popover` is the only one: it reaches the
 * page through MUI's own `Menu`, never through a line of product code, so
 * asserting its presence would assert a fiction.
 */
const DECLARED_NOT_IMPORTED = ['Popover'];

/**
 * Named survivors: MUI still rendered, with the gap that keeps them alive.
 * Every one of these traces to a single missing component. When the library
 * ships a segmented control, all of these rows go at once.
 */
const SURVIVORS = Object.entries(EXEMPTED)
  .filter(([symbol, why]) => why.startsWith('#24') && !DECLARED_NOT_IMPORTED.includes(symbol))
  .map(([symbol, why]) => ({
    symbol,
    file: SEARCH_FIELD,
    retiredBy: `LIBRARY-FEEDBACK ${why}`,
  }));

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

  it('the search field imports no MUI symbol outside the allow-list and the two exemptions', () => {
    // `Stack` and `Box` were here and are not: pure MUI layout inside the one
    // MUI control left in the bar. They are absent from both lists, so putting
    // either back fails this test rather than passing unnoticed.
    for (const symbol of importedSymbols(SOURCES.get(SEARCH_FIELD) as string)) {
      expect(
        { ...ALLOWED, ...EXEMPTED },
        `${symbol} is imported by ${SEARCH_FIELD}: allow it with a reason, or exempt it with the component the library owes`,
      ).toHaveProperty(symbol);
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

  it('sizes the loader from the slot it sits in, not by eye', () => {
    const search = read('src/components/SearchInput.jsx');
    // The sibling rows render a 20px glyph in the same icon slot, which is the
    // library's `md`. Nothing is being encircled here, so the 32px `xl` tier
    // would not be sitting in anything.
    expect(search).toMatch(/<Spinner size="md"/);
    expect(search).not.toMatch(/<Spinner size="(sm|lg|xl)"/);
  });

  it('leaves the unread marker on the library default tone', () => {
    const bar = SOURCES.get('src/private/components/nav/TopBar.tsx') as string;
    const badge = /<Badge[\s\S]*?\/?>/.exec(bar);
    expect(badge).not.toBeNull();
    // The library made `error` the default deliberately. Overriding it is a
    // design decision, so it may not arrive silently: state the tone here the
    // day it is chosen.
    expect(badge![0]).not.toMatch(/\btone=/);
  });

  it('states the search window through the named constants', () => {
    const bar = SOURCES.get('src/private/components/nav/TopBar.tsx') as string;
    expect(bar).toMatch(/minWidth: TOP_BAR_SEARCH_MIN_WIDTH/);
    expect(bar).toMatch(/maxWidth: TOP_BAR_SEARCH_MAX_WIDTH/);
  });
});
