import { MESSAGING$ } from '../../../relay/environment';

/**
 * Rail geometry and collapsed-state contract for the left navigation.
 *
 * This module exists so the contract does not live in the navigation
 * component itself. Seven unrelated floating toolbars import these widths to
 * align themselves with the rail, and ten components read the storage key
 * directly; when the navigation was a single 869-line file they all imported
 * from it, which made deleting that file impossible without touching them.
 * Keep this module free of React and of component imports.
 */

/**
 * Width of the collapsed rail, in pixels.
 *
 * This is the design system's own collapsed width (`w-12` = 12 * 0.25rem =
 * 48px), not the 55px the legacy MUI rail used. It is defined by the library
 * component, so it is read from here rather than chosen by the product: if it
 * ever changes, this constant is the single place to follow it, and the
 * unit test in navBarConstants.test.ts asserts the rendered rail matches.
 */
export const SMALL_BAR_WIDTH = 48;

/** Width of the expanded rail, in pixels (the library's `w-45` = 180px). */
export const OPEN_BAR_WIDTH = 180;

/** localStorage key holding the collapsed/expanded state of the rail. */
export const NAV_OPEN_STORAGE_KEY = 'navOpen';

/** localStorage key holding the ids of the currently expanded submenus. */
export const SELECTED_MENU_STORAGE_KEY = 'selectedMenu';

/**
 * Reads the persisted rail state. Anything other than the exact string
 * `'true'` — absent key, corrupted value, `'TRUE'` — resolves to collapsed,
 * which is the behaviour every existing consumer already relies on.
 */
export const readNavOpen = (): boolean => localStorage.getItem(NAV_OPEN_STORAGE_KEY) === 'true';

/**
 * Persists the rail state and notifies both kinds of listener that exist in
 * the application: components subscribed to `MESSAGING$.toggleNav`, and
 * components listening for a `storage` event. The synthetic event is required
 * because the browser only fires the real one in *other* tabs.
 */
export const writeNavOpen = (navOpen: boolean): void => {
  localStorage.setItem(NAV_OPEN_STORAGE_KEY, String(navOpen));
  window.dispatchEvent(new StorageEvent('storage', { key: NAV_OPEN_STORAGE_KEY }));
  MESSAGING$.toggleNav.next('toggle');
};

/** Reads the persisted expanded-submenu ids, tolerating a corrupted value. */
export const readSelectedMenu = (): string[] => {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(SELECTED_MENU_STORAGE_KEY) ?? '[]');
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : [];
  } catch {
    return [];
  }
};

/** Persists the expanded-submenu ids. */
export const writeSelectedMenu = (menus: string[]): void => {
  localStorage.setItem(SELECTED_MENU_STORAGE_KEY, JSON.stringify(menus));
};
