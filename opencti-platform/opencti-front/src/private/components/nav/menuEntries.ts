import type { MenuEntry } from '../common/menus/menuEntry';

// Convention: any `*.entries.ts(x)` file default-exporting its `MenuEntry[]` is collected here, nothing to register
// (menuEntries.test.ts fails if one forgets the default export, which would silently drop its pages from menus and search).
// Eagerly imported: those files are pure data (no component import), so the cost is negligible.
export const entriesModules = import.meta.glob<MenuEntry[]>('/src/private/components/**/*.entries.{ts,tsx}', { eager: true, import: 'default' });

export const allMenuEntries: MenuEntry[] = Object.values(entriesModules).flatMap((entries) => entries ?? []);

/**
 * Capabilities opening a page (or a section): the union of the `requiredCapabilities` of the entries under `path`.
 * Single source for route guards, so they cannot drift from the menus and the search. Any ONE of them is enough.
 *
 * Fails closed: a path without entries (typo, page not declared yet) yields `[]`, and `useGranted` denies an empty
 * list for everyone, except BYPASS users who pass every check before the list is even read.
 */
export const capabilitiesOf = (path: string): string[] => [...new Set(
  allMenuEntries
    .filter((entry) => entry.path === path || entry.path.startsWith(`${path}/`))
    .flatMap((entry) => entry.requiredCapabilities ?? []),
)];
