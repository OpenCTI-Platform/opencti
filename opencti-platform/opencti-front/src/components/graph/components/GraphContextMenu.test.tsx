import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import GraphContextMenu from './GraphContextMenu';

describe('GraphContextMenu', () => {
  it('lists the actions of each section under its name, says why one cannot run, and runs the chosen one', async () => {
    const hide = vi.fn();
    const onClose = vi.fn();
    const { user } = testRender(
      <GraphContextMenu
        anchor={{ x: 40, y: 60 }}
        label="Graph actions"
        onClose={onClose}
        sections={[
          { key: 'node', label: 'APT-X', actions: [{ id: 'hide', label: 'Hide', icon: <span />, onSelect: hide }] },
          { key: 'graph', label: 'Graph', actions: [{ id: 'clear', label: 'Clear selection', icon: <span />, shortcut: 'Esc', disabledReason: 'Nothing is selected' }] },
          { key: 'empty', label: 'Nothing to offer', actions: [] },
        ]}
      />,
    );
    const menu = await screen.findByRole('menu', { name: 'Graph actions' });
    expect(within(menu).getByText('APT-X')).toBeInTheDocument();
    expect(within(menu).queryByText('Nothing to offer')).toBeNull();
    expect(within(menu).getByRole('menuitem', { name: /Clear selection/ })).toHaveAttribute('aria-disabled', 'true');
    expect(within(menu).getByText('Nothing is selected')).toBeInTheDocument();
    await user.click(within(menu).getByRole('menuitem', { name: /Hide/ }));
    expect(hide).toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it('offers a choice as a submenu', async () => {
    testRender(
      <GraphContextMenu
        anchor={{ x: 0, y: 0 }}
        label="Graph actions"
        onClose={vi.fn()}
        sections={[{
          key: 'graph',
          actions: [{ id: 'select-by-type', label: 'Select by entity type', icon: <span />, options: { items: [{ key: 'Malware', label: 'Malware' }], onSelect: vi.fn() } }],
        }]}
      />,
    );
    const menu = await screen.findByRole('menu', { name: 'Graph actions' });
    expect(within(menu).getByRole('menuitem', { name: /Select by entity type/ })).toHaveAttribute('aria-haspopup', 'menu');
  });

  it('opens nothing without a place to open or without an action', () => {
    const { unmount } = testRender(
      <GraphContextMenu anchor={null} label="Graph actions" onClose={vi.fn()} sections={[{ key: 'a', actions: [{ id: 'x', label: 'X', icon: <span /> }] }]} />,
    );
    expect(screen.queryByRole('menu')).toBeNull();
    unmount();
    testRender(<GraphContextMenu anchor={{ x: 0, y: 0 }} label="Graph actions" onClose={vi.fn()} sections={[{ key: 'a', actions: [] }]} />);
    expect(screen.queryByRole('menu')).toBeNull();
  });
});
