import { MESSAGING$ } from '../../../relay/environment';

export const SMALL_BAR_WIDTH = 48;

export const OPEN_BAR_WIDTH = 180;

export const NAV_OPEN_STORAGE_KEY = 'navOpen';

export const SELECTED_MENU_STORAGE_KEY = 'selectedMenu';

export const readNavOpen = (): boolean => localStorage.getItem(NAV_OPEN_STORAGE_KEY) === 'true';

export const writeNavOpen = (navOpen: boolean): void => {
  localStorage.setItem(NAV_OPEN_STORAGE_KEY, String(navOpen));
  window.dispatchEvent(new StorageEvent('storage', { key: NAV_OPEN_STORAGE_KEY }));
  MESSAGING$.toggleNav.next('toggle');
};

export const readSelectedMenu = (): string[] => {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(SELECTED_MENU_STORAGE_KEY) ?? '[]');
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : [];
  } catch {
    return [];
  }
};

export const writeSelectedMenu = (menus: string[]): void => {
  localStorage.setItem(SELECTED_MENU_STORAGE_KEY, JSON.stringify(menus));
};
