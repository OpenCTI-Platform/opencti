import { describe, expect, it } from 'vitest';
import { PLAYBOOK_SHORTCUTS, playbookShortcutFor } from './playbookShortcuts';

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

  it('lists every action once in the cheat sheet', () => {
    const actions = PLAYBOOK_SHORTCUTS.map((shortcut) => shortcut.action);
    expect(new Set(actions).size).toBe(actions.length);
    expect(actions).toEqual(['zoomIn', 'zoomOut', 'fitView', 'verticalLayout', 'horizontalLayout', 'cheatSheet']);
  });
});
