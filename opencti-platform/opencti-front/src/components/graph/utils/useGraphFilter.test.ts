import { describe, expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import useGraphFilter from './useGraphFilter';
import { createCollapseCache, isGroupNode, withCollapsedGroups } from './graphCollapse';
import { graphLink, graphNode } from '../../../utils/tests/graphTestData';
import type { GraphState } from '../graph.types';

const context = vi.hoisted(() => ({ current: {} as unknown }));
vi.mock('../GraphContext', () => ({ useGraphContext: () => context.current }));

const actor = graphNode({ id: 'actor', entity_type: 'Intrusion-Set' });
const m1 = graphNode({ id: 'm1', entity_type: 'Malware' });
const m2 = graphNode({ id: 'm2', entity_type: 'Malware' });
const variant = graphLink(m1, m2, { relationship_type: 'variant-of', entity_type: 'variant-of' });
const graphData = { nodes: [actor, m1, m2], links: [graphLink(actor, m1), graphLink(actor, m2), variant] };

const filters = (overrides: Partial<GraphState> = {}) => ({
  disabledEntityTypes: [],
  disabledCreators: [],
  disabledMarkings: [],
  selectedTimeRangeInterval: undefined,
  disabledRelationshipTypes: [],
  ...overrides,
});

describe('useGraphFilter', () => {
  it('sets the flags once the filters are committed and changes its token, so a collapsed group follows its members', () => {
    context.current = { graphData, graphState: filters() };
    const cache = createCollapseCache();
    const { result, rerender } = renderHook(() => {
      const token = useGraphFilter();
      const group = withCollapsedGroups(graphData, ['Malware'], (type, count) => `${count} ${type}`, cache).nodes.find(isGroupNode);
      return { token, groupDisabled: group?.disabled };
    });
    expect(result.current.groupDisabled).toBe(false);
    const firstToken = result.current.token;

    context.current = { graphData, graphState: filters({ disabledEntityTypes: ['Malware'] }) };
    rerender();
    expect(result.current.groupDisabled).toBe(true);
    expect(result.current.token).not.toBe(firstToken);
  });

  it('keeps its token while neither the filters nor the data change', () => {
    context.current = { graphData, graphState: filters() };
    const { result, rerender } = renderHook(() => useGraphFilter());
    const firstToken = result.current;
    rerender();
    expect(result.current).toBe(firstToken);
  });

  it('fades the links of a relationship type turned off, not the entities they join', () => {
    context.current = { graphData, graphState: filters({ disabledRelationshipTypes: ['variant-of'] }) };
    renderHook(() => useGraphFilter());
    expect(variant.disabled).toBe(true);
    expect(m2.disabled).toBe(false);
  });
});
