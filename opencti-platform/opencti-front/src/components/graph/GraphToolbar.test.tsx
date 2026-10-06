import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import { GraphProvider } from './GraphContext';
import { type GraphViewActions, GraphViewContext } from './GraphViewContext';
import GraphToolbar from './GraphToolbar';
import GraphToolbarItem from './components/GraphToolbarItem';
import GraphToolbarOptionsList from './components/GraphToolbarOptionsList';

// The search field of the platform needs the assistant context; a plain field stands for it.
vi.mock('../SearchInput', () => ({ default: () => <input aria-label="Search" /> }));

const viewActions = (): GraphViewActions => ({
  counters: [{ key: 'entities', label: '2 entities', action: 'Select the entities', onSelect: vi.fn() }],
  drawnTypes: { entityTypes: [], relationshipTypes: [] },
  typeFilterCount: 0,
  drawnHasCycle: false,
  exportImage: vi.fn(),
  toggleFullscreen: vi.fn(),
  showShortcuts: vi.fn(),
});

const renderToolbar = (view = viewActions(), context: 'correlation' | 'analyses' = 'correlation') => ({
  view,
  ...testRender(
    <GraphProvider objects={[]} context={context}>
      <GraphViewContext.Provider value={view}>
        <GraphToolbar />
      </GraphViewContext.Provider>
    </GraphProvider>,
  ),
});

describe('GraphToolbar', () => {
  it('opens with the counters and groups the actions by intent, toggles announced as pressed', () => {
    renderToolbar();
    const toolbar = screen.getByRole('toolbar', { name: 'Graph toolbar' });
    expect(within(toolbar).getByRole('group', { name: 'Graph summary' })).toBeInTheDocument();
    ['View', 'Layout', 'Selection', 'Creation and removal', 'Filters', 'Export', 'Help'].forEach((name) => {
      expect(within(toolbar).getByRole('group', { name })).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: 'Fit the whole graph' })).toHaveAttribute('aria-keyshortcuts', 'F');
    expect(screen.getByRole('button', { name: 'Force-directed layout' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('button', { name: '3D mode' })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByRole('button', { name: 'Show only correlated observables and indicators' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('button', { name: 'Zoom in' })).not.toHaveAttribute('aria-pressed');
  });

  it('measures every fixed part, the divider before the creation tools included, to plan its room', () => {
    renderToolbar();
    const toolbar = screen.getByRole('toolbar', { name: 'Graph toolbar' });
    const creation = within(toolbar).getByRole('group', { name: 'Creation and removal' });
    expect(creation).toHaveAttribute('data-toolbar-pinned');
    const divider = creation.previousElementSibling;
    expect(divider).toHaveAttribute('data-toolbar-pinned');
    expect(divider?.children).toHaveLength(1);
    expect(divider?.firstElementChild).toHaveAttribute('aria-hidden', 'true');
  });

  it('leaves the search and the creation and removal tools out of the read-only analyses graph', () => {
    renderToolbar(viewActions(), 'analyses');
    const toolbar = screen.getByRole('toolbar', { name: 'Graph toolbar' });
    expect(within(toolbar).queryByRole('textbox', { name: 'Search' })).toBeNull();
    expect(within(toolbar).queryByRole('group', { name: 'Creation and removal' })).toBeNull();
  });

  it('offers the high-resolution export only to a user allowed to export', () => {
    renderToolbar({ ...viewActions(), exportImage: undefined });
    expect(screen.queryByRole('button', { name: 'Export the whole graph as a high-resolution image' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Keyboard shortcuts' })).toBeInTheDocument();
  });

  it('sits on the elevated surface of the legend and the details panel', () => {
    renderToolbar();
    const surface = screen.getByRole('toolbar', { name: 'Graph toolbar' }).closest('[data-graph-toolbar]');
    expect(surface).toHaveClass('layer-2', 'rounded-none', 'border-t');
    expect(surface).toHaveStyle({ position: 'fixed' });
  });

  it('keeps one fit action and disables what cannot run, saying why', () => {
    renderToolbar();
    expect(screen.getAllByRole('button', { name: /^Fit/ }).map((button) => button.getAttribute('aria-label'))).toEqual(['Fit the whole graph', 'Fit the selection']);
    ['Fit the selection', 'Filter by type', 'Clear all filters'].forEach((name) => {
      expect(screen.getByRole('button', { name })).toHaveAttribute('aria-disabled', 'true');
    });
    expect(screen.getByRole('button', { name: 'Fit the selection' })).toHaveAccessibleDescription('Select entities first');
    expect(screen.getByRole('button', { name: 'Clear all filters' })).toHaveAccessibleDescription('No filter is active');
  });

  it('offers to clear a stored filter the counts leave out, like a type filtered out that is not drawn', () => {
    localStorage.setItem('graph-toolbar-test', JSON.stringify({ disabledEntityTypes: ['Malware'] }));
    try {
      testRender(
        <GraphProvider objects={[]} context="correlation" localStorageKey="graph-toolbar-test">
          <GraphViewContext.Provider value={viewActions()}>
            <GraphToolbar />
          </GraphViewContext.Provider>
        </GraphProvider>,
      );
      expect(screen.getByRole('button', { name: 'Clear all filters' })).not.toHaveAttribute('aria-disabled', 'true');
    } finally {
      localStorage.removeItem('graph-toolbar-test');
    }
  });

  it('keeps the disabled actions in the keyboard path of the toolbar, where they do nothing', async () => {
    const { user } = renderToolbar();
    const fitSelection = screen.getByRole('button', { name: 'Fit the selection' });
    const fitGraph = screen.getByRole('button', { name: 'Fit the whole graph' });
    fitGraph.focus();
    await user.keyboard('{ArrowRight}');
    expect(fitSelection).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(fitSelection).toHaveAttribute('aria-disabled', 'true');
  });

  it('leaves the rare actions of a graph view to its context menu: "More actions" holds only what has no room', () => {
    renderToolbar();
    expect(screen.queryByRole('button', { name: 'Select all nodes' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'More actions' })).toBeNull();
  });

  it('lists the rare actions in "More actions", by group, for a toolbar outside a graph view', async () => {
    const { user } = testRender(
      <GraphProvider objects={[]} context="correlation">
        <GraphToolbar />
      </GraphProvider>,
    );
    expect(screen.queryByRole('button', { name: 'Select all nodes' })).toBeNull();
    await user.click(screen.getByRole('button', { name: 'More actions' }));
    const menu = await screen.findByRole('menu', { name: 'More actions' });
    expect(within(menu).getByText('Layout')).toBeInTheDocument();
    expect(within(menu).getByRole('menuitem', { name: /Unfix the nodes and re-apply forces/ })).not.toHaveAttribute('aria-disabled');
    expect(within(menu).getByRole('menuitem', { name: /Select all nodes/ })).toHaveAttribute('aria-keyshortcuts', 'Ctrl+A');
    // Without a selection, the relationships of the selection cannot be selected: the item says why.
    const relationships = within(menu).getByRole('menuitem', { name: /Select the relationships of the selected nodes/ });
    expect(relationships).toHaveAttribute('aria-disabled', 'true');
    expect(relationships).toHaveTextContent('Select entities first');
  });

  it('runs the actions of the graph view and drives the legend state', async () => {
    const { user, view } = renderToolbar();
    await user.click(screen.getByRole('button', { name: 'Full screen' }));
    expect(view.toggleFullscreen).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole('button', { name: 'Export the whole graph as a high-resolution image' }));
    expect(view.exportImage).toHaveBeenCalledTimes(1);
    const legend = screen.getByRole('button', { name: 'Legend' });
    const opened = legend.getAttribute('aria-pressed');
    await user.click(legend);
    expect(screen.getByRole('button', { name: 'Legend' })).not.toHaveAttribute('aria-pressed', opened ?? '');
  });

  it('is one tab stop, the arrow keys moving between its controls', async () => {
    const { user } = renderToolbar();
    const toolbar = screen.getByRole('toolbar', { name: 'Graph toolbar' });
    const stops = () => within(toolbar).getAllByRole('button').filter((button) => button.getAttribute('tabindex') === '0');
    expect(stops()).toHaveLength(1);
    const [first] = stops();
    first.focus();
    await user.keyboard('{ArrowRight}');
    expect(document.activeElement).not.toBe(first);
    expect(toolbar.contains(document.activeElement)).toBe(true);
    expect(document.activeElement).toHaveAttribute('tabindex', '0');
    await user.keyboard('{ArrowLeft}');
    expect(document.activeElement).toBe(first);
  });

  it('disables the tree layouts of a graph with a cycle in 3D, where they cannot apply, saying why', async () => {
    const { user } = renderToolbar({ ...viewActions(), drawnHasCycle: true });
    const vertical = () => screen.getByRole('button', { name: 'Hierarchical layout (top to bottom)' });
    expect(vertical()).not.toHaveAttribute('aria-disabled', 'true');
    await user.click(screen.getByRole('button', { name: '3D mode' }));
    expect(vertical()).toHaveAttribute('aria-disabled', 'true');
    expect(vertical()).toHaveAccessibleDescription('The graph has a cycle: use this layout in 2D mode');
    expect(screen.getByRole('button', { name: 'Hierarchical layout (left to right)' })).toHaveAttribute('aria-disabled', 'true');
    await user.click(screen.getByRole('button', { name: '3D mode' }));
  });
});

describe('GraphToolbarItem with a list', () => {
  const renderList = (multiple: boolean) => {
    const onSelect = vi.fn();
    const options = {
      multiple,
      onSelect,
      items: [
        { key: 'entity:Malware', label: 'Malware', section: 'Entities', selected: true },
        { key: 'entity:Report', label: 'Report', section: 'Entities', selected: false },
        { key: 'relationship:uses', label: 'uses', section: 'Relationships', selected: true },
      ],
    };
    const rendered = testRender(
      <GraphToolbarItem title="Filter by type" Icon={<span />} badge={1} menu={<GraphToolbarOptionsList options={options} />} />,
    );
    return { onSelect, ...rendered };
  };

  it('opens its choices in a menu anchored to the tool, by part, a multiple list staying open', async () => {
    const { user, onSelect } = renderList(true);
    const tool = screen.getByRole('button', { name: 'Filter by type' });
    expect(tool).toHaveAttribute('aria-haspopup', 'menu');
    await user.click(tool);
    const menu = await screen.findByRole('menu', { name: 'Filter by type' });
    expect(within(menu).getByText('Entities')).toBeInTheDocument();
    expect(within(menu).getByText('Relationships')).toBeInTheDocument();
    expect(within(menu).getByRole('menuitemcheckbox', { name: 'Malware' })).toHaveAttribute('aria-checked', 'true');
    await user.click(within(menu).getByRole('menuitemcheckbox', { name: 'Report' }));
    expect(onSelect).toHaveBeenCalledWith('entity:Report');
    expect(screen.getByRole('menu', { name: 'Filter by type' })).toBeInTheDocument();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('menu')).toBeNull();
    expect(tool).toHaveFocus();
  });

  it('closes a single-choice list on pick', async () => {
    const { user, onSelect } = renderList(false);
    await user.click(screen.getByRole('button', { name: 'Filter by type' }));
    const menu = await screen.findByRole('menu', { name: 'Filter by type' });
    await user.click(within(menu).getByRole('menuitem', { name: 'uses' }));
    expect(onSelect).toHaveBeenCalledWith('relationship:uses');
    expect(screen.queryByRole('menu')).toBeNull();
  });
});
