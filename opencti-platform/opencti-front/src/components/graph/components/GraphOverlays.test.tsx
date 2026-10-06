import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { graphLink, graphNode } from '../../../utils/tests/graphTestData';
import GraphLegend, { GraphLegendPill } from './GraphLegend';
import GraphCounters from './GraphCounters';
import GraphEmptyState from './GraphEmptyState';
import GraphHoverCard, { GraphHoverCardActions } from './GraphHoverCard';
import GraphAccessibleList, { ACCESSIBLE_LIST_WINDOW_RADIUS, graphElementKey } from './GraphAccessibleList';
import GraphShortcutsDialog from './GraphShortcutsDialog';
import { GROUP_LINK_PREFIX } from '../utils/graphCollapse';

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

  it('counts a nested relationship, drawn as a node, with the relationships of its type', () => {
    const nested = graphNode({ id: 'nested', entity_type: 'uses', relationship_type: 'uses', label: 'uses' });
    const connectors = [graphLink(actor, nested, { id: 'nested', label: '' }), graphLink(nested, malware, { id: 'nested', label: '' })];
    testRender(<GraphLegend {...props} nodes={[...props.nodes, nested]} links={[uses, ...connectors]} />);
    expect(screen.getByRole('button', { name: /uses: 2/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^uses: \d+.*entit/i })).toBeNull();
  });

  it('counts every relationship a link drawn towards a group stands for', () => {
    const group = graphNode({ id: 'group:Malware', entity_type: 'Malware', groupOf: { entityType: 'Malware', memberIds: ['malware', 'other'] } });
    const groupLink = graphLink(actor, group, { id: `${GROUP_LINK_PREFIX}actor|group:Malware|uses`, represents: 2 });
    testRender(<GraphLegend {...props} nodes={[actor, group]} links={[groupLink]} collapsedEntityTypes={['Malware']} />);
    expect(screen.getByRole('button', { name: /uses: 2/i })).toBeInTheDocument();
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

  it('stays under what is docked at the top, whatever the height of the graph', () => {
    testRender(<GraphLegend {...props} topOffset={220} bottomOffset={80} />);
    // What is docked at the top and the toolbar, plus the margins above and under the legend and the gap.
    expect(screen.getByRole('region', { name: 'Legend' }).style.maxHeight).toBe('calc(100% - 332px)');
  });

  it('minimizes from its header, saying what it folds and with which key', async () => {
    const onMinimize = vi.fn();
    const { user } = testRender(<GraphLegend {...props} onMinimize={onMinimize} />);
    const minimize = screen.getByRole('button', { name: 'Minimize the legend' });
    expect(minimize).toHaveAttribute('aria-expanded', 'true');
    expect(minimize).toHaveAttribute('aria-keyshortcuts', 'G');
    expect(document.getElementById(minimize.getAttribute('aria-controls') ?? '')).toHaveTextContent('Entities');
    await user.click(minimize);
    expect(onMinimize).toHaveBeenCalledTimes(1);
  });
});

describe('GraphLegendPill', () => {
  it('reopens the legend and counts the type filters in use', async () => {
    const onOpen = vi.fn();
    const { user, unmount } = testRender(<GraphLegendPill filterCount={2} bottomOffset={54} onOpen={onOpen} />);
    const pill = screen.getByRole('button', { name: 'Show the legend, 2 filters' });
    expect(pill).toHaveTextContent('Legend');
    expect(pill).toHaveAttribute('aria-expanded', 'false');
    expect(pill.closest('[data-graph-panel]')).not.toBeNull();
    await user.click(pill);
    expect(onOpen).toHaveBeenCalledTimes(1);
    unmount();
    testRender(<GraphLegendPill filterCount={0} onOpen={onOpen} />);
    expect(screen.getByRole('button', { name: 'Show the legend' })).not.toHaveTextContent('filter');
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
    expect(screen.getByRole('group', { name: 'Graph summary' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '124 entities - Select the entities' }));
    await user.click(screen.getByRole('button', { name: /^3 restricted/ }));
    expect(onSelectEntities).toHaveBeenCalledTimes(1);
    expect(onSelectRestricted).toHaveBeenCalledTimes(1);
  });

  it('draws nothing without a counter', () => {
    testRender(<GraphCounters counters={[]} />);
    expect(screen.queryByRole('group', { name: 'Graph summary' })).toBeNull();
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

  it('stays within a short graph and scrolls, so its last quick actions stay reachable', () => {
    testRender(
      <GraphHoverCard
        {...common}
        anchor={{ x: 10, y: 100 }}
        bounds={{ width: 1000, height: 150 }}
        target={{ kind: 'node', node: actor }}
        badges={[]}
        relationshipCounts={[]}
        actions={actions()}
      />,
    );
    expect(screen.getByRole('group', { name: 'Details on hover' })).toHaveStyle({ top: '0px', maxHeight: '150px', overflowY: 'auto' });
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
    // Its date is a placeholder of the platform, not a fact.
    expect(screen.queryByText('Date')).toBeNull();
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

  it('offers only the expansion on a collapsed group node, no fact or action of one of its entities', () => {
    // The group node carries the fields of its first member under a synthetic id.
    const group = graphNode({ ...actor, id: 'group:Intrusion-Set', label: '2 x Intrusion set', groupOf: { entityType: 'Intrusion-Set', memberIds: ['actor', 'other-actor'] } });
    testRender(<GraphHoverCard {...common} target={{ kind: 'node', node: group }} badges={[]} relationshipCounts={[]} actions={actions()} />);
    expect(screen.getByText('Collapsed group')).toBeInTheDocument();
    expect(screen.getAllByRole('button').map((button) => button.getAttribute('aria-label'))).toEqual(['Expand the group']);
    expect(screen.queryByText('APT-X')).toBeNull();
    expect(screen.queryByText('Date')).toBeNull();
  });

  it('offers no fact or action of a single relationship on a link drawn towards a group', () => {
    const groupLink = { ...uses, id: `${GROUP_LINK_PREFIX}actor|group:Malware|uses`, confidence: 15 };
    testRender(<GraphHoverCard {...common} target={{ kind: 'link', link: groupLink }} badges={[]} relationshipCounts={[]} actions={actions()} />);
    expect(screen.getByText(/APT-X/)).toBeInTheDocument();
    expect(screen.queryByRole('group', { name: 'Quick actions' })).toBeNull();
    expect(screen.queryByText('Confidence level')).toBeNull();
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
    testRender(<GraphAccessibleList nodes={[marked]} links={[]} selectedKeys={new Set()} onSelectNode={vi.fn()} onSelectLink={vi.fn()} />);
    // The most severe badge first, as on the canvas.
    expect(screen.getByRole('option', { name: 'Malware Qakbot, 0 relationships, Low confidence (20), TLP:AMBER' })).toBeInTheDocument();
  });

  it('counts a self-loop once in the relationships of its entity', () => {
    const loop = graphLink(malware, malware, { id: 'loop', relationship_type: 'variant-of', entity_type: 'variant-of' });
    testRender(<GraphAccessibleList nodes={[malware]} links={[loop]} selectedKeys={new Set()} onSelectNode={vi.fn()} onSelectLink={vi.fn()} />);
    expect(screen.getByRole('option', { name: /^Malware Emotet, 1 relationship$/ })).toBeInTheDocument();
  });

  it('counts every relationship a link drawn towards a group stands for', () => {
    const group = graphNode({ id: 'group:Malware', entity_type: 'Malware', groupOf: { entityType: 'Malware', memberIds: ['malware', 'other'] } });
    const groupLink = graphLink(actor, group, { id: `${GROUP_LINK_PREFIX}actor|group:Malware|uses`, represents: 2 });
    testRender(<GraphAccessibleList nodes={[actor, group]} links={[groupLink]} selectedKeys={new Set()} onSelectNode={vi.fn()} onSelectLink={vi.fn()} />);
    expect(screen.getByRole('option', { name: /APT-X, 2 relationships$/ })).toBeInTheDocument();
    // The link drawn towards the group says how many relationships it stands for.
    expect(screen.getAllByRole('option')).toHaveLength(3);
    expect(screen.getByRole('option', { name: /^APT-X .+ \(2 relationships\)$/ })).toBeInTheDocument();
  });

  it('tells the canvas which element the keyboard is on while the list has focus', async () => {
    const onActiveChange = vi.fn();
    const { user } = testRender(
      <GraphAccessibleList nodes={[actor, malware]} links={[uses]} selectedKeys={new Set()} onSelectNode={vi.fn()} onSelectLink={vi.fn()} onActiveChange={onActiveChange} />,
    );
    await user.tab();
    expect(onActiveChange).toHaveBeenLastCalledWith({ kind: 'node', id: 'actor' });
    await user.keyboard('{ArrowDown}{ArrowDown}');
    expect(onActiveChange).toHaveBeenLastCalledWith({ kind: 'link', id: 'uses-1', sourceId: 'actor', targetId: 'malware' });
    await user.tab();
    expect(onActiveChange).toHaveBeenLastCalledWith(null);
  });

  it('names the entities of a relationship whose endpoints are still ids', () => {
    // Links arrive with the ids of their endpoints; the renderer replaces them by nodes later.
    const pending = { ...uses, source: 'actor', target: 'malware' } as unknown as typeof uses;
    testRender(<GraphAccessibleList nodes={[actor, malware]} links={[pending]} selectedKeys={new Set()} onSelectNode={vi.fn()} onSelectLink={vi.fn()} />);
    expect(screen.getByRole('option', { name: 'APT-X uses Emotet' })).toBeInTheDocument();
  });

  it('mirrors each part of a nested relationship as its own option', () => {
    // A nested relationship is drawn as a node and two connector links, all three with its id.
    const nested = graphNode({ id: 'nested', label: 'related to', relationship_type: 'related-to', entity_type: 'related-to' });
    const links = [graphLink(actor, nested, { id: 'nested' }), graphLink(nested, malware, { id: 'nested' })];
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    testRender(<GraphAccessibleList nodes={[actor, nested, malware]} links={links} selectedKeys={new Set()} onSelectNode={vi.fn()} onSelectLink={vi.fn()} />);
    expect(screen.getAllByRole('option')).toHaveLength(5);
    expect(errors.mock.calls.some((call) => String(call[0]).includes('same key'))).toBe(false);
    errors.mockRestore();
  });

  it('announces only the selected part of a nested relationship as selected', () => {
    const nested = graphNode({ id: 'nested', label: 'related to', relationship_type: 'related-to', entity_type: 'related-to' });
    const [toNested, fromNested] = [graphLink(actor, nested, { id: 'nested' }), graphLink(nested, malware, { id: 'nested' })];
    testRender(
      <GraphAccessibleList
        nodes={[actor, nested, malware]}
        links={[toNested, fromNested]}
        selectedKeys={new Set([graphElementKey({ kind: 'link', link: fromNested })])}
        onSelectNode={vi.fn()}
        onSelectLink={vi.fn()}
      />,
    );
    const selected = screen.getAllByRole('option').filter((option) => option.getAttribute('aria-selected') === 'true');
    // The connector towards Emotet, neither the other connector nor the node sharing its id.
    expect(selected).toHaveLength(1);
    expect(selected[0]).toHaveTextContent(/Emotet$/);
  });

  it('mirrors the drawing as options a keyboard can select', () => {
    const onSelectNode = vi.fn();
    const onSelectLink = vi.fn();
    testRender(
      <GraphAccessibleList
        nodes={[actor, malware]}
        links={[uses]}
        selectedKeys={new Set([graphElementKey({ kind: 'node', node: malware })])}
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
        selectedKeys={new Set()}
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
    expect(screen.getByText('Search in the graph')).toBeInTheDocument();
  });

  it('leaves the search shortcut out of a graph without a search field', () => {
    testRender(<GraphShortcutsDialog open onClose={vi.fn()} searchable={false} />);
    expect(screen.getByText('Fit the selection')).toBeInTheDocument();
    expect(screen.queryByText('Search in the graph')).toBeNull();
  });

  it('leaves the export shortcut out for a user not allowed to export', () => {
    testRender(<GraphShortcutsDialog open onClose={vi.fn()} exportable={false} />);
    expect(screen.getByText('Fit the selection')).toBeInTheDocument();
    expect(screen.queryByText('Export the whole graph as a high-resolution image')).toBeNull();
  });
});
