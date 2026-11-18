import { describe, expect, it } from 'vitest';
import { displayShortcutKey, MOD_KEY, PLAYBOOK_SHORTCUTS, playbookShortcutFor } from './playbookShortcuts';

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

  it('shows the platform modifier: ⌘ on Apple platforms, Ctrl elsewhere', () => {
    expect(displayShortcutKey(MOD_KEY, 'MacIntel')).toBe('⌘');
    expect(displayShortcutKey(MOD_KEY, 'macOS')).toBe('⌘');
    expect(displayShortcutKey(MOD_KEY, 'iPhone')).toBe('⌘');
    expect(displayShortcutKey(MOD_KEY, 'Win32')).toBe('Ctrl');
    expect(displayShortcutKey(MOD_KEY, 'Linux x86_64')).toBe('Ctrl');
    expect(displayShortcutKey(MOD_KEY, undefined)).toBe('Ctrl');
    expect(displayShortcutKey('Z', 'MacIntel')).toBe('Z');
    const undo = PLAYBOOK_SHORTCUTS.find((shortcut) => shortcut.action === 'undo');
    expect(undo?.keys).toEqual([MOD_KEY, 'Z']);
  });

  it('lists every action once in the cheat sheet', () => {
    const actions = PLAYBOOK_SHORTCUTS.map((shortcut) => shortcut.action);
    expect(new Set(actions).size).toBe(actions.length);
    expect(actions).toEqual(['zoomIn', 'zoomOut', 'fitView', 'verticalLayout', 'horizontalLayout', 'undo', 'redo', 'cheatSheet']);
  });
});
