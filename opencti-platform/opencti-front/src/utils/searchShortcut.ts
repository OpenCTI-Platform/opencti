import { IS_MAC } from './keyboard';

/**
 * The keyboard shortcut focusing the top bar search. `ctrl` and `meta` (Command on macOS, Windows key elsewhere)
 * are distinct modifiers. `shift` only matters for letters: on some layouts a symbol such as `/` needs Shift
 * (AZERTY), which must not change what the shortcut is. Alt / Option is not supported: it composes other characters
 * (Option + "." gives "≥" on macOS) and its physical key cannot be labelled reliably on every layout.
 */
export interface SearchShortcut {
  key: string;
  ctrl: boolean;
  meta: boolean;
  shift: boolean;
}

export const DEFAULT_SEARCH_SHORTCUT: SearchShortcut = { key: '/', ctrl: false, meta: false, shift: false };

/** Id of the top bar search field, the target of the shortcut. */
export const TOP_BAR_SEARCH_ID = 'top-bar-search';

const isLetter = (key: string) => /^\p{L}$/u.test(key);

type KeyEventLike = Pick<KeyboardEvent, 'key' | 'ctrlKey' | 'metaKey' | 'altKey' | 'shiftKey'>;

export const matchesSearchShortcut = (event: KeyEventLike, shortcut: SearchShortcut): boolean => (
  event.key.toLowerCase() === shortcut.key
  && event.ctrlKey === shortcut.ctrl
  && event.metaKey === shortcut.meta
  && !event.altKey
  && (!isLetter(shortcut.key) || event.shiftKey === shortcut.shift)
);

/** Keys that cannot be a shortcut at all: modifiers alone, and keys with a fixed role in every form. */
const NOT_A_SHORTCUT = ['Control', 'Shift', 'Alt', 'AltGraph', 'Meta', 'CapsLock', 'Dead', 'Process', 'Unidentified', 'Tab', 'Escape', 'Enter', 'Backspace', 'Delete'];

/**
 * The shortcut a key press stands for, or `null` when it cannot be one. A bare key is only accepted when it is a
 * symbol (`/`, `?`...): letters, digits, space and named keys (arrows, F-keys...) need Ctrl or Command, otherwise
 * the shortcut would hijack typing or navigation.
 */
export const searchShortcutFromEvent = (event: KeyEventLike): SearchShortcut | null => {
  if (event.altKey || NOT_A_SHORTCUT.includes(event.key)) return null;
  const key = event.key.toLowerCase();
  const isSymbol = key.length === 1 && !/[\p{L}\p{N}\s]/u.test(key);
  if (!event.ctrlKey && !event.metaKey && !isSymbol) return null;
  return { key, ctrl: event.ctrlKey, meta: event.metaKey, shift: isLetter(key) && event.shiftKey };
};

const KEY_LABELS: Record<string, string> = { ' ': 'Space', arrowup: '↑', arrowdown: '↓', arrowleft: '←', arrowright: '→' };

/** "Ctrl+K", "⌘K", "/" */
export const formatSearchShortcut = (shortcut: SearchShortcut, isMac = IS_MAC): string => {
  const key = KEY_LABELS[shortcut.key] ?? (shortcut.key.length === 1 ? shortcut.key.toUpperCase() : shortcut.key);
  // macOS order: ⌃⇧⌘
  const parts = [
    ...(shortcut.ctrl ? [isMac ? '⌃' : 'Ctrl'] : []),
    ...(shortcut.shift ? [isMac ? '⇧' : 'Shift'] : []),
    ...(shortcut.meta ? [isMac ? '⌘' : 'Meta'] : []),
    key,
  ];
  return parts.join(isMac ? '' : '+');
};

/** Value of `aria-keyshortcuts`, which spells modifiers out ("Control+K"). */
export const ariaKeyShortcuts = (shortcut: SearchShortcut): string => [
  ...(shortcut.ctrl ? ['Control'] : []),
  ...(shortcut.meta ? ['Meta'] : []),
  ...(shortcut.shift ? ['Shift'] : []),
  shortcut.key.length === 1 ? shortcut.key.toUpperCase() : shortcut.key,
].join('+');

// ── Storage: local to the browser, `null` means the user turned the shortcut off ──────────────────
const DISABLED = 'disabled';

export const serializeSearchShortcut = (shortcut: SearchShortcut | null): string => (shortcut ? JSON.stringify(shortcut) : DISABLED);

/** Anything missing or unreadable falls back to the default: a broken value must not leave the user without a shortcut. */
export const parseSearchShortcut = (raw: string | null): SearchShortcut | null => {
  if (raw === null) return DEFAULT_SEARCH_SHORTCUT;
  if (raw === DISABLED) return null;
  try {
    const { key, ctrl, meta, alt, shift } = JSON.parse(raw);
    if (typeof key === 'string' && key !== '' && !alt && [ctrl, meta, shift].every((flag) => typeof flag === 'boolean')) {
      return { key, ctrl, meta, shift };
    }
  } catch {
    // not JSON: default below
  }
  return DEFAULT_SEARCH_SHORTCUT;
};
