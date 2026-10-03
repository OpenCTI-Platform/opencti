import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { graphLink, graphNode } from '../../../utils/tests/graphTestData';
import GraphLegend from './GraphLegend';
import GraphControls from './GraphControls';
import GraphHoverCard, { GraphHoverCardActions } from './GraphHoverCard';
import GraphAccessibleList from './GraphAccessibleList';
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
});

describe('GraphShortcutsDialog', () => {
  it('lists the keyboard shortcuts', () => {
    testRender(<GraphShortcutsDialog open onClose={vi.fn()} />);
    expect(screen.getByText('Fit the selection')).toBeInTheDocument();
    expect(screen.getAllByText('Shift').length).toBeGreaterThan(0);
  });
});
