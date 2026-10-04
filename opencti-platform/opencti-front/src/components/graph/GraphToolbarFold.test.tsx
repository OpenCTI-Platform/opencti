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
vi.mock('../../utils/hooks/useResizeObserver', () => ({ default: () => ({ width: 400, height: 54 }) }));

const view: GraphViewActions = {
  counters: [{ key: 'entities', label: '2 entities', action: 'Select the entities', onSelect: vi.fn() }],
  drawnTypes: { entityTypes: [], relationshipTypes: [] },
  typeFilterCount: 0,
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
