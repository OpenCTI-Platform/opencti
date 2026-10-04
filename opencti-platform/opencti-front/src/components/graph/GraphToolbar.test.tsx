import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import { GraphProvider } from './GraphContext';
import { type GraphViewActions, GraphViewContext } from './GraphViewContext';
import GraphToolbar from './GraphToolbar';

// The search field of the platform needs the assistant context; a plain field stands for it.
vi.mock('../SearchInput', () => ({ default: () => <input aria-label="Search" /> }));

const viewActions = (): GraphViewActions => ({
  counters: [{ key: 'entities', label: '2 entities', action: 'Select the entities', onSelect: vi.fn() }],
  typeFilterCount: 0,
  exportImage: vi.fn(),
  toggleFullscreen: vi.fn(),
  showShortcuts: vi.fn(),
});

const renderToolbar = (view = viewActions()) => ({
  view,
  ...testRender(
    <GraphProvider objects={[]} context="correlation">
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
    expect(screen.getByRole('button', { name: 'Forces' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('button', { name: '3D mode' })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByRole('button', { name: 'Show only correlated observables and indicators' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('button', { name: 'Zoom in' })).not.toHaveAttribute('aria-pressed');
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

  it('lists the rare actions in "More actions" only, by group', async () => {
    const { user } = renderToolbar();
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
});
