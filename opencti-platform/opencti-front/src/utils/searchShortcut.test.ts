import { describe, expect, it } from 'vitest';
import {
  ariaKeyShortcuts,
  DEFAULT_SEARCH_SHORTCUT,
  formatSearchShortcut,
  matchesSearchShortcut,
  parseSearchShortcut,
  SearchShortcut,
  searchShortcutFromEvent,
  serializeSearchShortcut,
} from './searchShortcut';

const press = (key: string, mods: Partial<{ ctrlKey: boolean; metaKey: boolean; altKey: boolean; shiftKey: boolean }> = {}) => ({
  key, ctrlKey: false, metaKey: false, altKey: false, shiftKey: false, ...mods,
});
const shortcut = (key: string, mods: Partial<SearchShortcut> = {}): SearchShortcut => ({
  key, ctrl: false, meta: false, shift: false, ...mods,
});

describe('matchesSearchShortcut', () => {
  it('matches the default "/" on a QWERTY keyboard and on AZERTY, where "/" needs Shift', () => {
    expect(matchesSearchShortcut(press('/'), DEFAULT_SEARCH_SHORTCUT)).toBe(true);
    expect(matchesSearchShortcut(press('/', { shiftKey: true }), DEFAULT_SEARCH_SHORTCUT)).toBe(true);
  });

  it('does not match when a modifier differs', () => {
    expect(matchesSearchShortcut(press('/', { ctrlKey: true }), DEFAULT_SEARCH_SHORTCUT)).toBe(false);
    expect(matchesSearchShortcut(press('x'), DEFAULT_SEARCH_SHORTCUT)).toBe(false);
  });

  it('tells Ctrl and Command apart, ignores the case, and compares Shift for letters', () => {
    const ctrlK = shortcut('k', { ctrl: true });
    expect(matchesSearchShortcut(press('k', { ctrlKey: true }), ctrlK)).toBe(true);
    expect(matchesSearchShortcut(press('K', { ctrlKey: true }), ctrlK)).toBe(true);
    expect(matchesSearchShortcut(press('k', { metaKey: true }), ctrlK)).toBe(false);
    expect(matchesSearchShortcut(press('k', { metaKey: true }), shortcut('k', { meta: true }))).toBe(true);
    expect(matchesSearchShortcut(press('K', { ctrlKey: true, shiftKey: true }), ctrlK)).toBe(false);
    expect(matchesSearchShortcut(press('K', { ctrlKey: true, shiftKey: true }), { ...ctrlK, shift: true })).toBe(true);
  });

  it('never matches while Alt / Option is held', () => {
    expect(matchesSearchShortcut(press('/', { altKey: true }), DEFAULT_SEARCH_SHORTCUT)).toBe(false);
  });
});

describe('searchShortcutFromEvent', () => {
  it('accepts a bare symbol, and a letter or named key with Ctrl / Command', () => {
    expect(searchShortcutFromEvent(press('/'))).toEqual(DEFAULT_SEARCH_SHORTCUT);
    expect(searchShortcutFromEvent(press('K', { metaKey: true }))).toEqual(shortcut('k', { meta: true }));
    expect(searchShortcutFromEvent(press('F2', { ctrlKey: true }))).toEqual(shortcut('f2', { ctrl: true }));
  });


  it('keeps Shift for letters only: "?" on a keyboard needing Shift is still just "?"', () => {
    expect(searchShortcutFromEvent(press('?', { shiftKey: true }))?.shift).toBe(false);
    expect(searchShortcutFromEvent(press('K', { ctrlKey: true, shiftKey: true }))?.shift).toBe(true);
  });

  it.each([
    ['a bare letter', press('k')],
    ['a bare digit', press('1')],
    ['space', press(' ')],
    ['a bare arrow', press('ArrowDown')],
    ['Alt + letter', press('k', { altKey: true })],
    ['Option + symbol (composed character)', press('≥', { altKey: true })],
    ['Ctrl + Alt', press('k', { altKey: true, ctrlKey: true })],
    ['a modifier alone', press('Control', { ctrlKey: true })],
    ['Escape', press('Escape')],
    ['Tab', press('Tab', { ctrlKey: true })],
    ['Enter', press('Enter')],
  ])('refuses %s', (_, event) => {
    expect(searchShortcutFromEvent(event)).toBeNull();
  });
});

describe('formatSearchShortcut', () => {
  it('formats for Windows / Linux and for macOS', () => {
    expect(formatSearchShortcut(DEFAULT_SEARCH_SHORTCUT, false)).toBe('/');
    expect(formatSearchShortcut(shortcut('k', { ctrl: true }), false)).toBe('Ctrl+K');
    expect(formatSearchShortcut(shortcut('k', { ctrl: true }), true)).toBe('⌃K');
    expect(formatSearchShortcut(shortcut('k', { meta: true }), true)).toBe('⌘K');
    expect(formatSearchShortcut(shortcut('k', { ctrl: true, shift: true }), false)).toBe('Ctrl+Shift+K');
    expect(formatSearchShortcut(shortcut('arrowup', { meta: true }), true)).toBe('⌘↑');
  });

  it('spells modifiers out for aria-keyshortcuts', () => {
    expect(ariaKeyShortcuts(DEFAULT_SEARCH_SHORTCUT)).toBe('/');
    expect(ariaKeyShortcuts(shortcut('k', { ctrl: true }))).toBe('Control+K');
    expect(ariaKeyShortcuts(shortcut('k', { meta: true }))).toBe('Meta+K');
  });
});

describe('stored shortcut', () => {
  it('round-trips, and null (disabled by the user) is not the default', () => {
    const ctrlK = shortcut('k', { ctrl: true });
    expect(parseSearchShortcut(serializeSearchShortcut(ctrlK))).toEqual(ctrlK);
    expect(parseSearchShortcut(serializeSearchShortcut(null))).toBeNull();
  });

  it('falls back to the default when nothing is stored or the value is broken', () => {
    expect(parseSearchShortcut(null)).toEqual(DEFAULT_SEARCH_SHORTCUT);
    expect(parseSearchShortcut('not json')).toEqual(DEFAULT_SEARCH_SHORTCUT);
    expect(parseSearchShortcut('{"key":"k"}')).toEqual(DEFAULT_SEARCH_SHORTCUT);
    expect(parseSearchShortcut('{"key":"","ctrl":true,"meta":false,"shift":false}')).toEqual(DEFAULT_SEARCH_SHORTCUT);
    expect(parseSearchShortcut('{"key":".","ctrl":false,"meta":false,"alt":true,"shift":false}')).toEqual(DEFAULT_SEARCH_SHORTCUT);
  });
});
