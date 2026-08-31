import { MESSAGING$ } from '../../../relay/environment';

/**
 * Rail geometry and collapsed-state contract for the left navigation.
 */

/**
 * Width of the collapsed rail, in pixels.
 */
export const SMALL_BAR_WIDTH = 48;

/** Width of the expanded rail, in pixels (the library's `w-45` = 180px). */
export const OPEN_BAR_WIDTH = 180;

/** localStorage key holding the collapsed/expanded state of the rail. */
export const NAV_OPEN_STORAGE_KEY = 'navOpen';

/** localStorage key holding the ids of the currently expanded submenus. */
export const SELECTED_MENU_STORAGE_KEY = 'selectedMenu';

/**
 * Reads the persisted rail state.
 */
export const readNavOpen = (): boolean => localStorage.getItem(NAV_OPEN_STORAGE_KEY) === 'true';

/**
 * Persists the rail state and notifies both kinds of listener that exist in the application:
 * components subscribed to `MESSAGING$.toggleNav`, and components listening for a `storage`
 * event.
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
