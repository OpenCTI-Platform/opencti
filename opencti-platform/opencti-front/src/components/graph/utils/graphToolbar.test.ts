import { describe, expect, it } from 'vitest';
import { planToolbarOverflow, TOOLBAR_ACTION_WIDTH, TOOLBAR_DIVIDER_WIDTH } from './graphToolbarOverflow';
import { nextToolbarIndex, toolbarControls } from './useToolbarRovingFocus';

const candidates = [
  { id: 'zoom-in', group: 'view', priority: 30 },
  { id: 'fit', group: 'view', priority: 100 },
  { id: 'mode-3d', group: 'layout', priority: 75 },
  { id: 'select-all', group: 'selection', priority: 0 },
  { id: 'filter-types', group: 'filters', priority: 85 },
];
const room = (actions: number, groups: number) => actions * TOOLBAR_ACTION_WIDTH + groups * TOOLBAR_DIVIDER_WIDTH;

describe('planToolbarOverflow', () => {
  it('keeps every action but the rare ones when the toolbar is not measured yet', () => {
    expect([...planToolbarOverflow(candidates, Infinity)]).toEqual(['zoom-in', 'fit', 'mode-3d', 'filter-types']);
  });

  it('keeps the most important actions within the room, counting a divider per group opened', () => {
    expect([...planToolbarOverflow(candidates, room(2, 2))].sort()).toEqual(['filter-types', 'fit']);
    expect([...planToolbarOverflow(candidates, room(3, 3))].sort()).toEqual(['filter-types', 'fit', 'mode-3d']);
    // The fourth action joins an open group: no divider to pay.
    expect([...planToolbarOverflow(candidates, room(4, 3))].sort()).toEqual(['filter-types', 'fit', 'mode-3d', 'zoom-in']);
  });

  it('fills the room left with a cheaper action of a group already open', () => {
    const shown = planToolbarOverflow(
      [{ id: 'a', group: 'x', priority: 9 }, { id: 'b', group: 'y', priority: 8 }, { id: 'c', group: 'x', priority: 7 }],
      room(2, 1),
    );
    expect([...shown].sort()).toEqual(['a', 'c']);
  });

  it('sends everything to the menu when there is no room', () => {
    expect(planToolbarOverflow(candidates, 0).size).toBe(0);
  });
});

describe('toolbar roving focus', () => {
  it('moves with the arrow keys, wraps around, and jumps with Home and End', () => {
    expect(nextToolbarIndex('ArrowRight', 0, 3)).toBe(1);
    expect(nextToolbarIndex('ArrowRight', 2, 3)).toBe(0);
    expect(nextToolbarIndex('ArrowLeft', 0, 3)).toBe(2);
    expect(nextToolbarIndex('Home', 2, 3)).toBe(0);
    expect(nextToolbarIndex('End', 0, 3)).toBe(2);
    expect(nextToolbarIndex('Enter', 0, 3)).toBeNull();
    expect(nextToolbarIndex('ArrowRight', 0, 0)).toBeNull();
  });

  it('reaches the enabled controls only, in reading order', () => {
    const root = document.createElement('div');
    root.innerHTML = '<button>A</button><button disabled>B</button><span aria-hidden="true"><button>C</button></span><input aria-label="D" /><div role="button">E</div>';
    expect(toolbarControls(root).map((control) => control.textContent || control.getAttribute('aria-label'))).toEqual(['A', 'D', 'E']);
  });
});
