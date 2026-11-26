import type { MenuEntry } from '../common/menus/menuEntry';

// Convention: any `*.entries.ts(x)` file default-exporting its `MenuEntry[]` is collected here, nothing to register
// (menuEntries.test.ts fails if one forgets the default export, which would silently drop its pages from menus and search).
// Eagerly imported: those files are pure data (no component import), so the cost is negligible.
export const entriesModules = import.meta.glob<MenuEntry[]>('/src/private/components/**/*.entries.{ts,tsx}', { eager: true, import: 'default' });

export const allMenuEntries: MenuEntry[] = Object.values(entriesModules).flatMap((entries) => entries ?? []);

/**
 * The entries of a page (or of a section: every page under `path`). What `EntryGuard` asks the visibility rules about,
 * so a route cannot drift from the menus and the search.
 * `exact`: only the entry at `path`, not the ones under it (a page that is also the parent of others, like Parameters).
 *
 * A path without entries (typo, page not declared yet) yields `[]`, which the guard denies.
 */
export const entriesUnder = (path: string, { exact = false }: { exact?: boolean } = {}): MenuEntry[] => allMenuEntries
  .filter((entry) => entry.path === path || (!exact && entry.path.startsWith(`${path}/`)));
