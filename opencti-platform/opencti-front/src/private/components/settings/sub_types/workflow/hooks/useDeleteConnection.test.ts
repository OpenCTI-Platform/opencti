import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Edge, Node } from 'reactflow';
import useDeleteConnection from './useDeleteConnection';
import { WorkflowNodeType } from '../utils';

const node = (id: string, type: WorkflowNodeType): Node => ({ id, type, data: {}, position: { x: 0, y: 0 } });
const edge = (source: string, target: string): Edge => ({ id: `e-${source}->${target}`, source, target, type: WorkflowNodeType.transition });

let graph: { nodes: Node[]; edges: Edge[] };
const mockSetNodes = vi.fn();
const mockSetEdges = vi.fn();

// Stable functions, like the memoised instance React Flow returns.
const mockGetNodes = () => graph.nodes;
const mockGetEdges = () => graph.edges;
vi.mock('reactflow', () => ({
  useReactFlow: () => ({ getNodes: mockGetNodes, getEdges: mockGetEdges, setNodes: mockSetNodes, setEdges: mockSetEdges }),
}));

describe('useDeleteConnection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    graph = {
      nodes: [node('NEW', WorkflowNodeType.status), node('DONE', WorkflowNodeType.status), node('submit', WorkflowNodeType.transition)],
      edges: [edge('NEW', 'submit'), edge('submit', 'DONE')],
    };
  });

  it('reads the graph when it runs, not when it was created', () => {
    const { result } = renderHook(() => useDeleteConnection());
    // The graph changes after the hook was created (another edit landed in between).
    graph = { ...graph, edges: [...graph.edges, edge('DONE', 'submit')] };

    act(() => result.current('e-NEW->submit'));

    expect(mockSetNodes).toHaveBeenCalledWith(graph.nodes);
    expect(mockSetEdges).toHaveBeenCalledWith([edge('submit', 'DONE'), edge('DONE', 'submit')]);
  });

  it('removes the transition with its last source', () => {
    const { result } = renderHook(() => useDeleteConnection());

    act(() => result.current('e-NEW->submit'));

    expect(mockSetNodes).toHaveBeenCalledWith([graph.nodes[0], graph.nodes[1]]);
    expect(mockSetEdges).toHaveBeenCalledWith([]);
  });

  it('keeps the same callback across renders', () => {
    const { result, rerender } = renderHook(() => useDeleteConnection());
    const first = result.current;
    rerender();
    expect(result.current).toBe(first);
  });
});
