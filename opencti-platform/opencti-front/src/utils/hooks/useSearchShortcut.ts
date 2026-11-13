import { useMemo, useSyncExternalStore } from 'react';
import { parseSearchShortcut, SearchShortcut, serializeSearchShortcut } from '../searchShortcut';

const STORAGE_KEY = 'search-shortcut';
const listeners = new Set<() => void>();

const readRaw = () => {
  try {
    return window.localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
};

// The `storage` event reaches the other tabs only: the listeners set covers this one.
const subscribe = (listener: () => void) => {
  listeners.add(listener);
  window.addEventListener('storage', listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener('storage', listener);
  };
};

/** Saves the shortcut for this browser (`null` turns it off). ponytail: lost if the storage is refused, nothing falls back to memory. */
export const writeSearchShortcut = (shortcut: SearchShortcut | null) => {
  try {
    window.localStorage.setItem(STORAGE_KEY, serializeSearchShortcut(shortcut));
  } catch {
    // Storage refused (private mode, quota): the default stays.
  }
  listeners.forEach((listener) => listener());
};

/** The shortcut focusing the top bar search: the user's choice, the default if none, `null` if turned off. */
const useSearchShortcut = (): SearchShortcut | null => {
  const raw = useSyncExternalStore(subscribe, readRaw, () => null);
  return useMemo(() => parseSearchShortcut(raw), [raw]);
};

export default useSearchShortcut;
