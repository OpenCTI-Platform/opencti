import { describe, expect, it } from 'vitest';
import { isApplePlatform, isGlobalShortcut, MOD_KEY, PLAYBOOK_SHORTCUTS, playbookShortcutFor, shortcutKeyLabel } from './playbookShortcuts';

// A DOM-like target: a tag, a role and the selectors of the ancestors it sits in.
const target = (tagName: string, role: string | null = null, insideOf: string[] = []) => ({
  tagName,
  getAttribute: (name: string) => (name === 'role' ? role : null),
  closest: (selectors: string) => (insideOf.some((selector) => selectors.includes(selector)) ? {} : null),
}) as unknown as EventTarget;

describe('playbookShortcutFor', () => {
  it('maps the canvas keys, both cases', () => {
    expect(playbookShortcutFor({ key: '+' })).toBe('zoomIn');
    expect(playbookShortcutFor({ key: '=' })).toBe('zoomIn');
    expect(playbookShortcutFor({ key: '-' })).toBe('zoomOut');
    expect(playbookShortcutFor({ key: 'f' })).toBe('fitView');
    expect(playbookShortcutFor({ key: 'F' })).toBe('fitView');
    expect(playbookShortcutFor({ key: 'v' })).toBe('verticalLayout');
    expect(playbookShortcutFor({ key: 'H' })).toBe('horizontalLayout');
    expect(playbookShortcutFor({ key: '?' })).toBe('cheatSheet');
    expect(playbookShortcutFor({ key: 'x' })).toBeNull();
  });

  it('undoes with Ctrl/Cmd+Z and redoes with Shift+Ctrl/Cmd+Z or Ctrl+Y', () => {
    expect(playbookShortcutFor({ key: 'z', ctrlKey: true })).toBe('undo');
    expect(playbookShortcutFor({ key: 'z', metaKey: true })).toBe('undo');
    expect(playbookShortcutFor({ key: 'Z', ctrlKey: true, shiftKey: true })).toBe('redo');
    expect(playbookShortcutFor({ key: 'z', metaKey: true, shiftKey: true })).toBe('redo');
    expect(playbookShortcutFor({ key: 'y', ctrlKey: true })).toBe('redo');
    expect(playbookShortcutFor({ key: 'z' })).toBeNull();
    expect(playbookShortcutFor({ key: 'z', ctrlKey: true, altKey: true })).toBeNull();
    expect(playbookShortcutFor({ key: 'z', ctrlKey: true, target: { tagName: 'INPUT' } as unknown as EventTarget })).toBeNull();
  });

  it('leaves the keys to the browser with a modifier', () => {
    expect(playbookShortcutFor({ key: '+', ctrlKey: true })).toBeNull();
    expect(playbookShortcutFor({ key: 'f', metaKey: true })).toBeNull();
    expect(playbookShortcutFor({ key: 'v', altKey: true })).toBeNull();
  });

  it('never fires while typing in a field', () => {
    expect(playbookShortcutFor({ key: 'f', target: { tagName: 'INPUT' } as unknown as EventTarget })).toBeNull();
    expect(playbookShortcutFor({ key: 'v', target: { tagName: 'textarea' } as unknown as EventTarget })).toBeNull();
    expect(playbookShortcutFor({ key: 'h', target: { tagName: 'DIV', isContentEditable: true } as unknown as EventTarget })).toBeNull();
    expect(playbookShortcutFor({ key: 'h', target: { tagName: 'DIV' } as unknown as EventTarget })).toBe('horizontalLayout');
  });

  it('leaves the keys to a select, a combobox, a list or a menu (their typeahead)', () => {
    expect(playbookShortcutFor({ key: 'h', target: target('BUTTON', 'combobox') })).toBeNull();
    expect(playbookShortcutFor({ key: 'h', target: target('DIV', 'listbox') })).toBeNull();
    expect(playbookShortcutFor({ key: 'h', target: target('LI', 'option') })).toBeNull();
    expect(playbookShortcutFor({ key: 'v', target: target('LI', 'menuitem') })).toBeNull();
    expect(playbookShortcutFor({ key: 'f', target: target('SELECT') })).toBeNull();
  });

  it('never fires inside a dialog or a drawer, undo and redo included', () => {
    expect(playbookShortcutFor({ key: 'h', target: target('BUTTON', null, ['[role="dialog"]']) })).toBeNull();
    expect(playbookShortcutFor({ key: 'f', target: target('DIV', null, ['.MuiDrawer-root']) })).toBeNull();
    expect(playbookShortcutFor({ key: 'z', ctrlKey: true, target: target('BUTTON', null, ['[aria-modal="true"]']) })).toBeNull();
    expect(playbookShortcutFor({ key: 'h', target: target('DIV', null) })).toBe('horizontalLayout');
  });

  it('keeps only undo and redo global', () => {
    expect(isGlobalShortcut('undo')).toBe(true);
    expect(isGlobalShortcut('redo')).toBe(true);
    for (const action of ['zoomIn', 'zoomOut', 'fitView', 'verticalLayout', 'horizontalLayout', 'cheatSheet'] as const) {
      expect(isGlobalShortcut(action)).toBe(false);
    }
  });

  it('shows the platform modifier: the Command sign on macOS, Ctrl elsewhere', () => {
    expect(isApplePlatform({ platform: 'MacIntel' })).toBe(true);
    expect(isApplePlatform({ userAgentData: { platform: 'macOS' } })).toBe(true);
    expect(isApplePlatform({ platform: 'iPhone' })).toBe(true);
    expect(isApplePlatform({ platform: 'Win32' })).toBe(false);
    expect(isApplePlatform({ platform: 'Linux x86_64' })).toBe(false);
    expect(shortcutKeyLabel(MOD_KEY, true)).toBe('\u2318');
    expect(shortcutKeyLabel(MOD_KEY, false)).toBe('Ctrl');
    expect(shortcutKeyLabel('Z', true)).toBe('Z');
    const labels = PLAYBOOK_SHORTCUTS.flatMap((shortcut) => shortcut.keys.map((key) => shortcutKeyLabel(key, false)));
    expect(labels.some((label) => label.includes('/'))).toBe(false);
  });

  it('lists every action once in the cheat sheet', () => {
    const actions = PLAYBOOK_SHORTCUTS.map((shortcut) => shortcut.action);
    expect(new Set(actions).size).toBe(actions.length);
    expect(actions).toEqual(['zoomIn', 'zoomOut', 'fitView', 'verticalLayout', 'horizontalLayout', 'undo', 'redo', 'cheatSheet']);
  });
});
