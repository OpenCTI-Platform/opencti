import { afterEach, describe, expect, it, vi } from 'vitest';
import { MESSAGING$ } from '../../../relay/environment';
import {
  NAV_OPEN_STORAGE_KEY,
  OPEN_BAR_WIDTH,
  readNavOpen,
  readSelectedMenu,
  SELECTED_MENU_STORAGE_KEY,
  SMALL_BAR_WIDTH,
  writeNavOpen,
  writeSelectedMenu,
} from './navBarConstants';

/**
 * These constants and helpers are a cross-component contract, not internals of the rail: seven
 * floating toolbars offset themselves by the widths, and ten components read the collapsed
 * flag straight out of localStorage.
 */
describe('navBarConstants', () => {
  afterEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it('exposes the rail widths the floating toolbars offset themselves by', () => {
    // 48 is the design-system rail's real collapsed width (`w-12`); 180 its
    // expanded width (`w-45`). A drift here silently misaligns seven toolbars.
    expect(SMALL_BAR_WIDTH).toBe(48);
    expect(OPEN_BAR_WIDTH).toBe(180);
  });

  it('keeps the storage keys the other readers already use', () => {
    expect(NAV_OPEN_STORAGE_KEY).toBe('navOpen');
    expect(SELECTED_MENU_STORAGE_KEY).toBe('selectedMenu');
  });

  it('defaults to a collapsed rail when nothing was ever persisted', () => {
    // Iso-functional with the component this replaced and with the ten other
    // readers, which all spell it `localStorage.getItem('navOpen') === 'true'`.
    expect(readNavOpen()).toBe(false);
  });

  it('round-trips the collapsed flag through localStorage', () => {
    writeNavOpen(false);
    expect(localStorage.getItem(NAV_OPEN_STORAGE_KEY)).toBe('false');
    expect(readNavOpen()).toBe(false);
    writeNavOpen(true);
    expect(readNavOpen()).toBe(true);
  });

  it('notifies the other readers on both channels', () => {
    const storageListener = vi.fn();
    window.addEventListener('storage', storageListener);
    const messagingSpy = vi.spyOn(MESSAGING$.toggleNav, 'next');

    writeNavOpen(false);

    // Same-document listeners never receive a native `storage` event, so the
    // synthetic one is what keeps cross-component readers in sync.
    expect(storageListener).toHaveBeenCalledTimes(1);
    expect(storageListener.mock.calls[0][0].key).toBe(NAV_OPEN_STORAGE_KEY);
    expect(messagingSpy).toHaveBeenCalledTimes(1);
    window.removeEventListener('storage', storageListener);
  });

  it('survives a corrupted selectedMenu entry instead of crashing the app', () => {
    localStorage.setItem(SELECTED_MENU_STORAGE_KEY, '{not json');
    expect(readSelectedMenu()).toEqual([]);
  });

  it('round-trips the expanded submenus', () => {
    writeSelectedMenu(['threats', 'arsenal']);
    expect(readSelectedMenu()).toEqual(['threats', 'arsenal']);
  });
});
