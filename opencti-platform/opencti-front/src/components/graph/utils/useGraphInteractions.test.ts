import { describe, expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import useGraphInteractions from './useGraphInteractions';
import { graphLink, graphNode } from '../../../utils/tests/graphTestData';
import type { GraphState } from '../graph.types';

const context = vi.hoisted(() => ({ current: {} as unknown }));
vi.mock('../GraphContext', () => ({ useGraphContext: () => context.current }));
vi.mock('./useGraphParser', () => ({ default: () => ({}) }));

const actor = graphNode({ id: 'actor', entity_type: 'Intrusion-Set' });
const m1 = graphNode({ id: 'm1', entity_type: 'Malware' });
const victim = graphNode({ id: 'victim', entity_type: 'Organization' });
const uses = graphLink(actor, m1, { id: 'uses' });
// Not yet given to the force graph: its ends are still identifiers.
const targets = { ...graphLink(actor, victim, { id: 'targets', relationship_type: 'targets', entity_type: 'targets' }), source: 'actor', target: 'victim' };

const renderInteractions = (initial: Partial<GraphState>) => {
  let graphState = { selectedNodes: [], selectedLinks: [], hiddenNodeIds: [], collapsedEntityTypes: [], ...initial } as unknown as GraphState;
  const setGraphState = (update: (old: GraphState) => GraphState) => {
    graphState = update(graphState);
  };
  context.current = { graphData: { nodes: [actor, m1, victim], links: [uses, targets] }, graphState, setGraphState };
  const { result } = renderHook(() => useGraphInteractions());
  return { interactions: result.current, state: () => graphState };
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
});
