import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const FILES = [
  'src/private/components/nav/TopBar.tsx',
  'src/private/components/nav/TopBarIconLink.tsx',
  'src/private/components/chatbox/AskArianeButton.tsx',
  'src/private/components/chatbox/CtemCommandCenterButton.tsx',
  'src/components/UploadImport.tsx',
];

const SEARCH_FIELD = 'src/components/SearchInput.jsx';

const read = (f: string) => readFileSync(path.resolve(f), 'utf8');
const SOURCES = new Map([...FILES, SEARCH_FIELD].map((f) => [f, read(f)]));

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

const RETIRED = ['MuiBadge-', 'MuiStack-', 'CircularProgress'];

const EXEMPTED: Record<string, string> = {
  // Segmented control — LIBRARY-FEEDBACK #24. All of these go together the day
  // the library ships one.
  ToggleButtonGroup: '#24 segmented control',
  ToggleButton: '#24 segmented control',
  // MUI's group injects `value`/`selected` into its children THROUGH the tooltip (measured: `data-mui-internal-
  // clone-element` on the wrapper, and `Mui-selected` arriving on the toggle).
  Tooltip: '#24 inside the segmented control cloning contract',
  // The agent dropdown hangs off the caret inside a `ToggleButton`; a Radix
  // trigger would have to nest a button inside a button.
  Menu: '#24 blocked by the same missing segmented control',
  MenuItem: '#24 blocked by the same missing segmented control',
  ListItemIcon: '#24 rows of that same menu',
  ListItemText: '#24 rows of that same menu',
  Popover: '#24 MUI draws the exempted menu with it; no library Popover yet',
  TextField: 'non-topBar variants only, never rendered in the bar',
};

const DECLARED_NOT_IMPORTED = ['Popover'];

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
    // `import makeStyles from '@mui/styles/makeStyles'` names the symbol in the path, not the
    // clause — count the path's tail too, so the module cannot be used as a back door.
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
      expect(ALLOWED, `${symbol} is imported by ${file} and is not an allowed MUI symbol`)
        .toHaveProperty(symbol);
    }
  });

  it('grants no exemption beyond the two that were named', () => {
    const NAMED = [
      '#24', // the segmented control, and everything that depends on it
      'non-topBar', // not the bar at all: other variants of a shared component
    ];
    for (const [symbol, why] of Object.entries(EXEMPTED)) {
      expect(
        NAMED.some((prefix) => why.startsWith(prefix)),
        `${symbol} is exempted for a reason that is neither named exemption`,
      ).toBe(true);
    }
  });

  it('the search field imports no MUI symbol outside the allow-list and the two exemptions', () => {
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
    expect(read(file)).toContain(symbol);
  });

  it('takes the bar controls from the library', () => {
    const bar = SOURCES.get('src/private/components/nav/TopBar.tsx') as string;
    for (const symbol of ['Header', 'HeaderGroup', 'IconButton', 'Menu']) {
      expect(bar).toMatch(new RegExp(`import \\{[^}]*\\b${symbol}\\b[^}]*\\} from '@filigran/design-system'`, 's'));
    }
    const link = SOURCES.get('src/private/components/nav/TopBarIconLink.tsx') as string;
    expect(link).toMatch(/import \{[^}]*\bBadge\b[^}]*\} from '@filigran\/design-system'/s);
  });

  it('marks the control with the badge, never the aria-hidden glyph', () => {
    const link = SOURCES.get('src/private/components/nav/TopBarIconLink.tsx') as string;
    expect(link).toMatch(/<Badge[^>]*\{\.\.\.badge\}>\{link\}<\/Badge>/);
    expect(link).not.toMatch(/<Badge[\s\S]*?\{icon\}/);
    const bar = SOURCES.get('src/private/components/nav/TopBar.tsx') as string;
    expect(bar).not.toMatch(/<Badge\b/);
  });

  it('forwards what asChild clones, so the tooltips actually open', () => {
    const link = SOURCES.get('src/private/components/nav/TopBarIconLink.tsx') as string;
    // Naming only the known props silently swallowed Radix's handlers and ref:
    // the Triggers and Notifications tooltips never opened.
    expect(link).toMatch(/React\.forwardRef</);
    expect(link).toMatch(/\.\.\.rest\s*\}?\s*,?\s*\}/);
    expect(link).toMatch(/\{\.\.\.rest\}/);
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
    expect(search).toMatch(/<Spinner size="md"/);
    expect(search).not.toMatch(/<Spinner size="(sm|lg|xl)"/);
  });

  it('leaves the unread marker on the library default tone', () => {
    const bar = SOURCES.get('src/private/components/nav/TopBar.tsx') as string;
    const call = /badge=\{\{[\s\S]*?\}\}/.exec(bar);
    expect(call).not.toBeNull();
    expect(call![0]).not.toMatch(/\btone\b/);
    const link = SOURCES.get('src/private/components/nav/TopBarIconLink.tsx') as string;
    expect(link).not.toMatch(/\btone[=:]/);
  });

  it('states the search window through the named constants', () => {
    const bar = SOURCES.get('src/private/components/nav/TopBar.tsx') as string;
    expect(bar).toMatch(/minWidth: TOP_BAR_SEARCH_MIN_WIDTH/);
    expect(bar).toMatch(/maxWidth: TOP_BAR_SEARCH_MAX_WIDTH/);
  });
});
