import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Node, Edge } from 'reactflow';
import useDeleteElement from './useDeleteElement';

const mockSetNodes = vi.fn();
const mockSetEdges = vi.fn();

vi.mock('reactflow', () => ({
  useReactFlow: () => ({
    setNodes: mockSetNodes,
    setEdges: mockSetEdges,
  }),
}));

describe('useDeleteElement', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should remove the node with the matching ID', () => {
    const { result } = renderHook(() => useDeleteElement());
    const nodeIdToDelete = 'node-to-delete';

    act(() => {
      result.current(nodeIdToDelete);
    });

    // Extract the updater function passed to setNodes
    expect(mockSetNodes).toHaveBeenCalledWith(expect.any(Function));
    const nodeUpdater = mockSetNodes.mock.calls[0][0] as (nds: Node[]) => Node[];

    // Define initial state
    const initialNodes: Node[] = [
      { id: 'node-to-delete', position: { x: 0, y: 0 }, data: {} },
      { id: 'node-to-keep', position: { x: 10, y: 10 }, data: {} },
    ];

    // Execute updater and verify result
    const resultNodes = nodeUpdater(initialNodes);
    expect(resultNodes).toHaveLength(1);
    expect(resultNodes[0].id).toBe('node-to-keep');
  });

  it('should remove all edges connected to the deleted node as source or target', () => {
    const { result } = renderHook(() => useDeleteElement());
    const nodeIdToDelete = 'node-A';

    act(() => {
      result.current(nodeIdToDelete);
    });

    // Extract the updater function passed to setEdges
    expect(mockSetEdges).toHaveBeenCalledWith(expect.any(Function));
    const edgeUpdater = mockSetEdges.mock.calls[0][0] as (eds: Edge[]) => Edge[];

    // Define initial state with various edge configurations
    const initialEdges: Edge[] = [
      { id: 'e1', source: 'node-A', target: 'node-B' }, // Source match
      { id: 'e2', source: 'node-C', target: 'node-A' }, // Target match
      { id: 'e3', source: 'node-B', target: 'node-C' }, // No match
    ];

    // Execute updater and verify result
    const resultEdges = edgeUpdater(initialEdges);
    expect(resultEdges).toHaveLength(1);
    expect(resultEdges[0].id).toBe('e3');
    expect(resultEdges.find((e) => e.source === 'node-A' || e.target === 'node-A')).toBeUndefined();
  });

  it('should not remove anything if the ID does not match', () => {
    const { result } = renderHook(() => useDeleteElement());

    act(() => {
      result.current('non-existent-id');
    });

    const nodeUpdater = mockSetNodes.mock.calls[0][0] as (nds: Node[]) => Node[];
    const edgeUpdater = mockSetEdges.mock.calls[0][0] as (eds: Edge[]) => Edge[];

    const initialNodes: Node[] = [{ id: '1', position: { x: 0, y: 0 }, data: {} }];
    const initialEdges: Edge[] = [{ id: 'e1', source: '1', target: '2' }];

    expect(nodeUpdater(initialNodes)).toHaveLength(1);
    expect(edgeUpdater(initialEdges)).toHaveLength(1);
  });
});
