import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, within } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import ToolbarShell, { type ToolbarAction, type ToolbarSlot } from './ToolbarShell';

// The row is as wide as each test sets it.
const row = vi.hoisted(() => ({ width: 2000 }));
vi.mock('../../utils/hooks/useResizeObserver', () => ({ default: () => ({ width: row.width, height: 54 }) }));
// Width drawn for each wide control, by action id; every other element measures 0.
const widths = vi.hoisted(() => ({ posture: 300 } as Record<string, number>));

type Group = 'a' | 'b' | 'posture';
const GROUPS: Group[] = ['a', 'b', 'posture'];
const LABELS: Record<Group, string> = { a: 'Group A', b: 'Group B', posture: 'Security posture' };

const icon = (id: string, group: Group, priority = 50): ToolbarAction<Group> => (
  { id, group, priority, label: id, icon: <span />, onSelect: vi.fn() }
);

const posture = (render = vi.fn(() => <button type="button">Kill chain</button>)): ToolbarAction<Group> => ({
  id: 'posture',
  group: 'posture',
  priority: 40,
  width: 300,
  label: 'Compare with my security posture',
  icon: <span />,
  render,
  submenu: () => <input aria-label="Platform" />,
});

const renderShell = (actions: ToolbarAction<Group>[], layout: ToolbarSlot<Group>[] = [
  { kind: 'group', group: 'a' },
  { kind: 'group', group: 'b' },
  { kind: 'group', group: 'posture' },
]) => {
  const element = (
    <ToolbarShell<Group>
      label="Test toolbar"
      layout={layout}
      actions={actions}
      groups={GROUPS}
      groupLabels={LABELS}
      height={54}
      pushMoreActionsRight
    />
  );
  return { element, ...testRender(element) };
};

describe('ToolbarShell', () => {
  beforeEach(() => {
    Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
      configurable: true,
      get() {
        const id = (this as HTMLElement).getAttribute('data-toolbar-action');
        return id ? (widths[id] ?? 0) : 0;
      },
    });
  });

  afterEach(() => {
    delete (HTMLElement.prototype as { offsetWidth?: number }).offsetWidth;
    row.width = 2000;
    widths.posture = 300;
  });

  it('draws the slots in order with a divider between groups, the first one without', () => {
    renderShell([icon('one', 'a'), icon('two', 'b')], [
      { kind: 'pinned', key: 'note', render: () => <span>Note</span> },
      { kind: 'group', group: 'a' },
      { kind: 'group', group: 'b' },
    ]);
    const toolbar = screen.getByRole('toolbar', { name: 'Test toolbar' });
    const children = Array.from(toolbar.children);
    expect(children[0]).toHaveTextContent('Note');
    expect(within(toolbar).getAllByRole('separator', { hidden: true })).toHaveLength(2);
    expect(within(toolbar).getByRole('group', { name: 'Group A' })).toContainElement(screen.getByRole('button', { name: 'one' }));
  });

  it('draws no divider before the first group when nothing is drawn before it', () => {
    renderShell([icon('one', 'a'), icon('two', 'b')]);
    const toolbar = screen.getByRole('toolbar', { name: 'Test toolbar' });
    expect(within(toolbar).getAllByRole('separator', { hidden: true })).toHaveLength(1);
  });

  it('draws every non-rare action while the row is not measured', () => {
    row.width = 0;
    renderShell([icon('one', 'a'), icon('two', 'b'), posture()]);
    expect(screen.getByRole('button', { name: 'one' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'two' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Kill chain' })).toBeInTheDocument();
  });

  it('measures a wide control and moves it to "More actions" as a submenu when it has no room', async () => {
    const { user, rerender, element } = renderShell([icon('one', 'a'), posture()]);
    expect(screen.getByRole('button', { name: 'Kill chain' })).toBeInTheDocument();
    row.width = 200;
    rerender(element);
    expect(screen.queryByRole('button', { name: 'Kill chain' })).toBeNull();
    await user.click(screen.getByRole('button', { name: 'More actions' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Compare with my security posture' }));
    expect(await screen.findByRole('textbox', { name: 'Platform' })).toBeInTheDocument();
  });

  it('keeps the width measured in the row while the control waits in "More actions"', () => {
    const render = vi.fn(() => <button type="button">Kill chain</button>);
    const { rerender, element } = renderShell([posture(render)]);
    // Measured at 300 px in a wide row; then the declared estimate is no longer used.
    widths.posture = 330;
    rerender(element);
    row.width = 200;
    rerender(element);
    expect(screen.queryByRole('button', { name: 'Kill chain' })).toBeNull();
    // The 300 px estimate and its divider would fit in this row; the 330 px measured do not.
    row.width = 360;
    rerender(element);
    expect(screen.queryByRole('button', { name: 'Kill chain' })).toBeNull();
    row.width = 1000;
    rerender(element);
    expect(screen.getByRole('button', { name: 'Kill chain' })).toBeInTheDocument();
    expect(render.mock.calls.length).toBeLessThan(10);
  });

  it('lets a field inside a submenu take the keys typed in it', async () => {
    row.width = 200;
    const { user } = renderShell([posture()]);
    await user.click(screen.getByRole('button', { name: 'More actions' }));
    // By keyboard: jsdom has no pointer grace area, so moving the pointer off the trigger closes the submenu.
    const trigger = await screen.findByRole('menuitem', { name: 'Compare with my security posture' });
    act(() => trigger.focus());
    await user.keyboard('{ArrowRight}');
    const input = await screen.findByRole('textbox', { name: 'Platform' });
    act(() => input.focus());
    await user.keyboard('ab');
    expect(input).toHaveValue('ab');
    // The arrow that closes a submenu moves the caret instead.
    await user.keyboard('{ArrowLeft}c');
    expect(input).toHaveValue('acb');
    expect(input).toHaveFocus();
  });

  it('reaches a wide control with the arrow keys', async () => {
    const { user } = renderShell([icon('one', 'a'), posture()]);
    screen.getByRole('button', { name: 'one' }).focus();
    await user.keyboard('{ArrowRight}');
    expect(screen.getByRole('button', { name: 'Kill chain' })).toHaveFocus();
  });
});
