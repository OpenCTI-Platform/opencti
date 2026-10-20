import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import { GraphProvider } from './GraphContext';
import { type GraphViewActions, GraphViewContext } from './GraphViewContext';
import GraphToolbar from './GraphToolbar';

// The search field of the platform needs the assistant context; a plain field stands for it.
vi.mock('../SearchInput', () => ({ default: () => <input aria-label="Search" /> }));
// A narrow graph: the row is 400 px wide and every fixed part of it 120 px.
const row = vi.hoisted(() => ({ width: 400 }));
vi.mock('../../utils/hooks/useResizeObserver', () => ({ default: () => ({ width: row.width, height: 54 }) }));
// A creation tool counting its mounts: the dialogs of the real tools live in their state.
const tool = vi.hoisted(() => ({ mounts: 0 }));
vi.mock('./components/GraphToolbarContentTools', () => ({
  default: () => {
    React.useEffect(() => {
      tool.mounts += 1;
    }, []);
    return <button type="button">Add an entity</button>;
  },
}));

const view: GraphViewActions = {
  counters: [{ key: 'entities', label: '2 entities', action: 'Select the entities', onSelect: vi.fn() }],
  drawnTypes: { entityTypes: [], relationshipTypes: [] },
  typeFilterCount: 0,
  drawnHasCycle: false,
  exportImage: vi.fn(),
  toggleFullscreen: vi.fn(),
  showShortcuts: vi.fn(),
};

describe('GraphToolbar on a narrow graph', () => {
  beforeEach(() => {
    Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
      configurable: true,
      get() {
        return (this as HTMLElement).hasAttribute('data-toolbar-pinned') ? 120 : 0;
      },
    });
  });

  afterEach(() => {
    delete (HTMLElement.prototype as { offsetWidth?: number }).offsetWidth;
    row.width = 400;
  });

  it('keeps the creation and removal tools mounted when the row folds or unfolds them', () => {
    row.width = 4000;
    const toolbarOf = () => (
      <GraphProvider objects={[]} context="correlation">
        <GraphViewContext.Provider value={view}>
          <GraphToolbar />
        </GraphViewContext.Provider>
      </GraphProvider>
    );
    tool.mounts = 0;
    const { rerender } = testRender(toolbarOf());
    const toolbar = screen.getByRole('toolbar', { name: 'Graph toolbar' });
    const inline = within(toolbar).getByRole('group', { name: 'Creation and removal' });
    const addEntity = within(inline).getByRole('button', { name: 'Add an entity' });
    expect(tool.mounts).toBe(1);
    // Folded then unfolded, the tool is the same: an open dialog of it would stay open
    row.width = 400;
    rerender(toolbarOf());
    expect(within(toolbar).getByRole('button', { name: 'Creation and removal' })).toBeInTheDocument();
    // Folded, the tool waits in the closed popover, out of the row and of its keyboard path
    expect(addEntity.isConnected).toBe(true);
    expect(toolbar.contains(addEntity)).toBe(false);
    row.width = 4000;
    rerender(toolbarOf());
    expect(within(toolbar).getByRole('button', { name: 'Add an entity' })).toBe(addEntity);
    expect(toolbar.contains(addEntity)).toBe(true);
    expect(tool.mounts).toBe(1);
  });

  it('folds the creation and removal tools into one button instead of clipping them', async () => {
    const { user } = testRender(
      <GraphProvider objects={[]} context="correlation">
        <GraphViewContext.Provider value={view}>
          <GraphToolbar />
        </GraphViewContext.Provider>
      </GraphProvider>,
    );
    const toolbar = screen.getByRole('toolbar', { name: 'Graph toolbar' });
    expect(within(toolbar).queryByRole('group', { name: 'Creation and removal' })).toBeNull();
    // Kept mounted while closed, the tools are out of reach until the button opens them.
    expect(screen.queryByRole('group', { name: 'Creation and removal' })).toBeNull();
    await user.click(within(toolbar).getByRole('button', { name: 'Creation and removal' }));
    expect(await screen.findByRole('group', { name: 'Creation and removal' })).toBeInTheDocument();
  });
});
