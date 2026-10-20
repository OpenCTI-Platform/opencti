import { describe, expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import useGraphInteractions from './useGraphInteractions';
import { graphLink, graphNode } from '../../../utils/tests/graphTestData';
import type { GraphState } from '../graph.types';

const context = vi.hoisted(() => ({ current: {} as unknown }));
vi.mock('../GraphContext', () => ({ useGraphContext: () => context.current }));
vi.mock('./useGraphParser', () => ({ default: () => ({ buildGraphData: () => ({ nodes: [], links: [] }) }) }));

const actor = graphNode({ id: 'actor', entity_type: 'Intrusion-Set' });
const m1 = graphNode({ id: 'm1', entity_type: 'Malware' });
const victim = graphNode({ id: 'victim', entity_type: 'Organization' });
const uses = graphLink(actor, m1, { id: 'uses' });
// Not yet given to the force graph: its ends are still identifiers.
const targets = { ...graphLink(actor, victim, { id: 'targets', relationship_type: 'targets', entity_type: 'targets' }), source: 'actor', target: 'victim' };

const renderInteractions = (initial: Partial<GraphState>, graphData: { nodes: unknown[]; links: unknown[] } = { nodes: [actor, m1, victim], links: [uses, targets] }) => {
  let graphState = { selectedNodes: [], selectedLinks: [], hiddenNodeIds: [], collapsedEntityTypes: [], ...initial } as unknown as GraphState;
  const setGraphState = (update: (old: GraphState) => GraphState) => {
    graphState = update(graphState);
  };
  const graph = {
    graphRef2D: { current: { d3ReheatSimulation: vi.fn() } },
    graphRef3D: { current: undefined },
    rawObjects: [],
    rawPositions: { actor: { x: 10, y: 20 } },
    setRawObjects: vi.fn(),
    setRawPositions: vi.fn(),
    setGraphData: vi.fn(),
  };
  context.current = { graphData, graphState, setGraphState, ...graph };
  const { result } = renderHook(() => useGraphInteractions());
  return { interactions: result.current, state: () => graphState, graph };
};

describe('useGraphInteractions', () => {
  it('drops a hidden entity and its relationships from the selection', () => {
    const { interactions, state } = renderInteractions({ selectedNodes: [m1, victim], selectedLinks: [uses, targets] });
    interactions.hideNodes(['victim']);
    expect(state().hiddenNodeIds).toEqual(['victim']);
    expect(state().selectedNodes.map((n) => n.id)).toEqual(['m1']);
    expect(state().selectedLinks.map((l) => l.id)).toEqual(['uses']);
  });

  it('drops the members of a collapsed type and their relationships from the selection', () => {
    const { interactions, state } = renderInteractions({ selectedNodes: [actor, m1], selectedLinks: [uses, targets] });
    interactions.toggleCollapsedEntityType('Malware');
    expect(state().collapsedEntityTypes).toEqual(['Malware']);
    expect(state().selectedNodes.map((n) => n.id)).toEqual(['actor']);
    expect(state().selectedLinks.map((l) => l.id)).toEqual(['targets']);
  });

  it('selects only the drawn relationships of the selected nodes, never one towards a hidden entity', () => {
    const { interactions, state } = renderInteractions({ selectedNodes: [actor], hiddenNodeIds: ['victim'], selectRelationshipMode: null });
    interactions.switchSelectRelationshipMode();
    expect(state().selectedLinks.map((l) => l.id)).toEqual(['uses']);
  });

  it('finds the shortest path through a collapsed type along the links drawn towards its group', () => {
    const m2 = graphNode({ id: 'm2', entity_type: 'Malware' });
    const delivers = graphLink(m2, victim, { id: 'delivers', relationship_type: 'delivers', entity_type: 'delivers' });
    const data = { nodes: [actor, m1, m2, victim], links: [uses, delivers] };
    const collapsed = renderInteractions({ collapsedEntityTypes: ['Malware'] }, data);
    expect(collapsed.interactions.highlightShortestPath('actor', 'victim')).toBe(true);
    expect(collapsed.state().highlightedPath?.nodeIds).toEqual(['actor', 'group:Malware', 'victim']);
    // Expanded, the two malware are not linked: neither are the two entities.
    expect(renderInteractions({}, data).interactions.highlightShortestPath('actor', 'victim')).toBe(false);
  });

  it('leaves every arrangement and forgets the saved positions when the nodes are unfixed', () => {
    const { interactions, state, graph } = renderInteractions({ layoutMode: 'tiers', modeTree: 'td' });
    interactions.unfixNodes();
    expect(state().layoutMode).toBeNull();
    expect(state().modeTree).toBeNull();
    expect(graph.setRawPositions).toHaveBeenCalledWith({});
    expect(graph.setGraphData).toHaveBeenCalled();
    expect(graph.graphRef2D.current.d3ReheatSimulation).toHaveBeenCalled();
  });
});
