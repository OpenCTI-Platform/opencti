import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { graphLink, graphNode } from '../../../utils/tests/graphTestData';
import GraphLegend from './GraphLegend';
import GraphControls from './GraphControls';
import GraphCounters from './GraphCounters';
import GraphEmptyState from './GraphEmptyState';
import GraphHoverCard, { GraphHoverCardActions } from './GraphHoverCard';
import GraphAccessibleList, { ACCESSIBLE_LIST_WINDOW_RADIUS } from './GraphAccessibleList';
import GraphShortcutsDialog from './GraphShortcutsDialog';

const actor = graphNode({ id: 'actor', entity_type: 'Intrusion-Set', label: 'APT-X', name: 'APT-X\n2025-01-01' });
const malware = graphNode({ id: 'malware', label: 'Emotet' });
const other = graphNode({ id: 'other', label: 'Trickbot' });
const uses = graphLink(actor, malware, { id: 'uses-1' });

describe('GraphLegend', () => {
  const props = {
    nodes: [actor, malware, other],
    links: [uses],
    disabledEntityTypes: [],
    disabledRelationshipTypes: [],
    collapsedEntityTypes: [],
    hiddenCount: 0,
    onToggleEntityType: vi.fn(),
    onToggleRelationshipType: vi.fn(),
    onToggleCollapsed: vi.fn(),
    onShowHidden: vi.fn(),
  };

  it('counts each entity type and relationship type, the counters acting as filters', async () => {
    const { user } = testRender(<GraphLegend {...props} />);
    const malwareRow = screen.getByRole('button', { name: /Malware: 2/ });
    expect(malwareRow).toHaveAttribute('aria-pressed', 'true');
    await user.click(malwareRow);
    expect(props.onToggleEntityType).toHaveBeenCalledWith('Malware');
    await user.click(screen.getByRole('button', { name: /uses: 1/i }));
    expect(props.onToggleRelationshipType).toHaveBeenCalledWith('uses');
    expect(screen.getByText('Line styles')).toBeInTheDocument();
  });

  it('collapses a type and shows the hidden entities', async () => {
    const { user } = testRender(<GraphLegend {...props} hiddenCount={2} collapsedEntityTypes={['Malware']} />);
    await user.click(screen.getByRole('button', { name: 'Expand the group' }));
    expect(props.onToggleCollapsed).toHaveBeenCalledWith('Malware');
    await user.click(screen.getByRole('button', { name: /Show the hidden entities/ }));
    expect(props.onShowHidden).toHaveBeenCalled();
  });

  it('lists only the badges present, each selecting the entities carrying it', async () => {
    const onSelectBadge = vi.fn();
    const { user, unmount } = testRender(
      <GraphLegend
        {...props}
        badges={[{ key: 'low-confidence', label: 'Low confidence', tone: 'warning', tooltip: 'Its confidence level is below 50', count: 2 }]}
        onSelectBadge={onSelectBadge}
      />,
    );
    expect(screen.getByText('Badges')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Low confidence: 2' }));
    expect(onSelectBadge).toHaveBeenCalledWith('low-confidence');
    unmount();
    testRender(<GraphLegend {...props} />);
    expect(screen.queryByText('Badges')).toBeNull();
  });

  it('stays above the time range selector of the toolbar when it is open', () => {
    testRender(<GraphLegend {...props} bottomOffset={80} />);
    expect(screen.getByRole('region', { name: 'Legend' }).style.marginBottom).toBe('80px');
  });

  it('stays under the controls and the counter row, whatever the height of the graph', () => {
    testRender(<GraphLegend {...props} topOffset={220} bottomOffset={80} />);
    // The row and the toolbar, plus the margins above and under the legend and the gap under the row.
    expect(screen.getByRole('region', { name: 'Legend' }).style.maxHeight).toBe('calc(100% - 332px)');
  });
});

describe('GraphEmptyState', () => {
  it('says why nothing is drawn and offers the next action', async () => {
    const onClearFilters = vi.fn();
    const onShowHidden = vi.fn();
    const { user, unmount } = testRender(<GraphEmptyState kind="filtered" onClearFilters={onClearFilters} onShowHidden={onShowHidden} />);
    expect(screen.getByRole('status')).toHaveTextContent('No entity matches these filters');
    await user.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(onClearFilters).toHaveBeenCalled();
    unmount();
    const hidden = testRender(<GraphEmptyState kind="hidden" onClearFilters={onClearFilters} onShowHidden={onShowHidden} />);
    await hidden.user.click(screen.getByRole('button', { name: 'Show the hidden entities' }));
    expect(onShowHidden).toHaveBeenCalled();
    hidden.unmount();
    testRender(<GraphEmptyState kind="empty" context="investigation" onClearFilters={onClearFilters} onShowHidden={onShowHidden} />);
    expect(screen.getByRole('status')).toHaveTextContent('Add entities to this investigation from the toolbar');
    expect(screen.getByRole('link', { name: 'Read the documentation' })).toHaveAttribute('href', 'https://docs.opencti.io/latest/usage/graphs/');
  });
});

describe('GraphCounters', () => {
  it('names each counter with what it selects and runs the selection', async () => {
    const onSelectEntities = vi.fn();
    const onSelectRestricted = vi.fn();
    const { user } = testRender(
      <GraphCounters
        counters={[
          { key: 'entities', label: '124 entities', action: 'Select the entities', onSelect: onSelectEntities },
          { key: 'restricted', label: '3 restricted', action: 'Select the entities you do not have access to', tone: 'neutral', onSelect: onSelectRestricted },
        ]}
      />,
    );
    expect(screen.getByRole('toolbar', { name: 'Graph summary' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '124 entities - Select the entities' }));
    await user.click(screen.getByRole('button', { name: /^3 restricted/ }));
    expect(onSelectEntities).toHaveBeenCalledTimes(1);
    expect(onSelectRestricted).toHaveBeenCalledTimes(1);
  });

  it('draws nothing without a counter', () => {
    testRender(<GraphCounters counters={[]} />);
    expect(screen.queryByRole('toolbar', { name: 'Graph summary' })).toBeNull();
  });
});

describe('GraphControls', () => {
  it('names every control with its shortcut and runs it', async () => {
    const handlers = {
      onZoomIn: vi.fn(),
      onZoomOut: vi.fn(),
      onFit: vi.fn(),
      onFitSelection: vi.fn(),
      onLocate: vi.fn(),
      onToggleLegend: vi.fn(),
      onToggleFullscreen: vi.fn(),
      onExport: vi.fn(),
      onShowShortcuts: vi.fn(),
    };
    const { user } = testRender(<GraphControls hasSelection={false} is3D={false} isFullscreen={false} showLegend {...handlers} />);
    expect(screen.getByRole('toolbar', { name: 'Graph view controls' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Zoom in' }));
    await user.click(screen.getByRole('button', { name: 'Fit the whole graph' }));
    await user.click(screen.getByRole('button', { name: 'Show the graph full screen' }));
    await user.click(screen.getByRole('button', { name: 'Export the whole graph as a high-resolution image' }));
    expect(handlers.onZoomIn).toHaveBeenCalled();
    expect(handlers.onFit).toHaveBeenCalled();
    expect(handlers.onToggleFullscreen).toHaveBeenCalled();
    expect(handlers.onExport).toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Fit the selection' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Fit the whole graph' })).toHaveAttribute('aria-keyshortcuts', 'F');
  });

  it('keeps only what works in 3D', () => {
    testRender(
      <GraphControls
        hasSelection
        is3D
        isFullscreen
        showLegend={false}
        onZoomIn={vi.fn()}
        onZoomOut={vi.fn()}
        onFit={vi.fn()}
        onFitSelection={vi.fn()}
        onLocate={vi.fn()}
        onToggleLegend={vi.fn()}
        onToggleFullscreen={vi.fn()}
        onExport={vi.fn()}
        onShowShortcuts={vi.fn()}
      />,
    );
    expect(screen.queryByRole('button', { name: 'Zoom in' })).toBeNull();
    expect(screen.queryByRole('button', { name: /Export the whole graph/ })).toBeNull();
    expect(screen.getByRole('button', { name: 'Leave full screen' })).toBeInTheDocument();
  });
});

describe('GraphHoverCard', () => {
  const actions = (): GraphHoverCardActions => ({
    onOpen: vi.fn(),
    onExpand: vi.fn(),
    onTogglePin: vi.fn(),
    onHide: vi.fn(),
    onSelectNeighbours: vi.fn(),
    onCentreRadial: vi.fn(),
    onPathFromSelection: vi.fn(),
    onRelateToSelection: vi.fn(),
    onExpandGroup: vi.fn(),
    onSelectLink: vi.fn(),
  });
  const common = {
    anchor: { x: 10, y: 10 },
    bounds: { width: 1000, height: 800 },
    isPinned: false,
    onMouseEnter: vi.fn(),
    onMouseLeave: vi.fn(),
  };

  it('names the node and offers its quick actions', async () => {
    const handlers = actions();
    const node = graphNode({ ...actor, confidence: 30, markedBy: [{ id: 'tlp', definition: 'TLP:GREEN', x_opencti_color: '#2e7d32' }] });
    const { user } = testRender(
      <GraphHoverCard
        {...common}
        target={{ kind: 'node', node }}
        context="investigation"
        badges={[{ key: 'tlp', tone: 'neutral', label: 'TLP:GREEN' }]}
        relationshipCounts={[{ type: 'uses', count: 2 }]}
        actions={handlers}
      />,
    );
    expect(screen.getByText('APT-X')).toBeInTheDocument();
    expect(screen.getAllByText('TLP:GREEN').length).toBeGreaterThan(0);
    expect(screen.getByText('30')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Open in a new tab' }));
    await user.click(screen.getByRole('button', { name: 'Expand this entity' }));
    await user.click(screen.getByRole('button', { name: 'Pin at its place' }));
    await user.click(screen.getByRole('button', { name: 'Hide from the view' }));
    await user.click(screen.getByRole('button', { name: 'Shortest path from the selection' }));
    expect(handlers.onOpen).toHaveBeenCalledWith('actor');
    expect(handlers.onExpand).toHaveBeenCalled();
    expect(handlers.onTogglePin).toHaveBeenCalled();
    expect(handlers.onHide).toHaveBeenCalled();
    expect(handlers.onPathFromSelection).toHaveBeenCalled();
  });

  it('starts an investigation from an entity, never from a relationship node', async () => {
    const handlers = { ...actions(), onStartInvestigation: vi.fn() };
    const node = graphNode({ ...actor });
    const { user, unmount } = testRender(
      <GraphHoverCard {...common} target={{ kind: 'node', node }} badges={[]} relationshipCounts={[]} actions={handlers} />,
    );
    await user.click(screen.getByRole('button', { name: 'Start an investigation' }));
    expect(handlers.onStartInvestigation).toHaveBeenCalledWith(node);
    unmount();
    const relationshipNode = graphNode({ id: 'rel', label: 'Uses', relationship_type: 'uses' });
    testRender(<GraphHoverCard {...common} target={{ kind: 'node', node: relationshipNode }} badges={[]} relationshipCounts={[]} actions={handlers} />);
    expect(screen.queryByRole('button', { name: 'Start an investigation' })).toBeNull();
  });

  it('lists every badge with what it means', () => {
    const node = graphNode({ ...actor });
    const badges = ['a', 'b', 'c', 'd'].map((key) => ({ key, tone: 'warning' as const, label: `Badge ${key}`, tooltip: `Meaning ${key}` }));
    testRender(<GraphHoverCard {...common} target={{ kind: 'node', node }} badges={badges} relationshipCounts={[]} actions={actions()} />);
    expect(screen.getAllByRole('listitem')).toHaveLength(4);
  });

  it('names a restricted entity "Restricted" and says why', () => {
    const node = graphNode({ id: 'restricted', label: 'Restricted', isRestricted: true });
    testRender(<GraphHoverCard {...common} target={{ kind: 'node', node }} badges={[]} relationshipCounts={[]} actions={actions()} />);
    expect(screen.getByText('Restricted')).toBeInTheDocument();
    expect(screen.getByText('You do not have access to this entity.')).toBeInTheDocument();
  });

  it('describes a relationship and a collapsed group', async () => {
    const handlers = actions();
    const { user, unmount } = testRender(
      <GraphHoverCard {...common} target={{ kind: 'link', link: { ...uses, confidence: 15 } }} badges={[]} relationshipCounts={[]} actions={handlers} />,
    );
    expect(screen.getByText(/APT-X/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Select this relationship' }));
    expect(handlers.onSelectLink).toHaveBeenCalled();
    unmount();
    const group = graphNode({ id: 'group:Malware', label: '2 x Malware', groupOf: { entityType: 'Malware', memberIds: ['m1', 'm2'] } });
    testRender(<GraphHoverCard {...common} target={{ kind: 'node', node: group }} badges={[]} relationshipCounts={[]} actions={handlers} />);
    fireEvent.click(screen.getByRole('button', { name: 'Expand the group' }));
    expect(handlers.onExpandGroup).toHaveBeenCalledWith('Malware');
  });
});

describe('GraphAccessibleList', () => {
  it('says the badges of an entity after its name and relationships', () => {
    const marked = graphNode({
      id: 'marked',
      label: 'Qakbot',
      confidence: 20,
      markedBy: [{ id: 'tlp-amber', definition: 'TLP:AMBER', x_opencti_color: '#ffc000' }] as never,
    });
    testRender(<GraphAccessibleList nodes={[marked]} links={[]} selectedIds={new Set()} onSelectNode={vi.fn()} onSelectLink={vi.fn()} />);
    // The most severe badge first, as on the canvas.
    expect(screen.getByRole('option', { name: 'Malware Qakbot, 0 relationships, Low confidence (20), TLP:AMBER' })).toBeInTheDocument();
  });

  it('counts a self-loop once in the relationships of its entity', () => {
    const loop = graphLink(malware, malware, { id: 'loop', relationship_type: 'variant-of', entity_type: 'variant-of' });
    testRender(<GraphAccessibleList nodes={[malware]} links={[loop]} selectedIds={new Set()} onSelectNode={vi.fn()} onSelectLink={vi.fn()} />);
    expect(screen.getByRole('option', { name: /^Malware Emotet, 1 relationship$/ })).toBeInTheDocument();
  });

  it('mirrors the drawing as options a keyboard can select', () => {
    const onSelectNode = vi.fn();
    const onSelectLink = vi.fn();
    testRender(
      <GraphAccessibleList
        nodes={[actor, malware]}
        links={[uses]}
        selectedIds={new Set(['malware'])}
        onSelectNode={onSelectNode}
        onSelectLink={onSelectLink}
      />,
    );
    const list = screen.getByRole('listbox', { name: 'Elements of the graph' });
    expect(screen.getAllByRole('option')).toHaveLength(3);
    expect(screen.getByRole('option', { name: /^Malware Emotet/ })).toHaveAttribute('aria-selected', 'true');
    fireEvent.keyDown(list, { key: 'Enter' });
    expect(onSelectNode).toHaveBeenCalledWith(actor, false);
    fireEvent.keyDown(list, { key: 'End' });
    fireEvent.keyDown(list, { key: 'Enter', shiftKey: true });
    expect(onSelectLink).toHaveBeenCalledWith(uses, true);
  });

  it('keeps every relationship of a large graph reachable while mounting only a window of options', () => {
    const onSelectLink = vi.fn();
    const many = Array.from({ length: 4000 }, (_, index) => graphLink(actor, malware, { id: `link-${index}` }));
    testRender(
      <GraphAccessibleList
        nodes={[actor, malware]}
        links={many}
        selectedIds={new Set()}
        onSelectNode={vi.fn()}
        onSelectLink={onSelectLink}
      />,
    );
    const list = screen.getByRole('listbox', { name: 'Elements of the graph' });
    expect(screen.getAllByRole('option').length).toBeLessThanOrEqual(2 * ACCESSIBLE_LIST_WINDOW_RADIUS + 1);
    fireEvent.keyDown(list, { key: 'End' });
    const active = document.getElementById(list.getAttribute('aria-activedescendant') ?? '');
    expect(active).toHaveAttribute('aria-posinset', '4002');
    expect(active).toHaveAttribute('aria-setsize', '4002');
    fireEvent.keyDown(list, { key: 'Enter' });
    expect(onSelectLink).toHaveBeenCalledWith(many[3999], false);
    fireEvent.keyDown(list, { key: 'PageUp' });
    fireEvent.keyDown(list, { key: 'Enter' });
    expect(onSelectLink).toHaveBeenLastCalledWith(many[3989], false);
  });
});

describe('GraphShortcutsDialog', () => {
  it('lists the keyboard shortcuts', () => {
    testRender(<GraphShortcutsDialog open onClose={vi.fn()} />);
    expect(screen.getByText('Fit the selection')).toBeInTheDocument();
    expect(screen.getAllByText('Shift').length).toBeGreaterThan(0);
  });
});
