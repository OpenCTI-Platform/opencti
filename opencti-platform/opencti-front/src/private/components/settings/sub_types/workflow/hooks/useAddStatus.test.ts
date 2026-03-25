import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Node, Edge } from 'reactflow';
import useAddStatus from './useAddStatus';
import { WorkflowNodeType } from '../utils';

// Helper for Mocking Placeholder Nodes
interface PlaceholderNode extends Node {
  source: string;
}

const hoisted = vi.hoisted(() => ({
  mockSetNodes: vi.fn(),
  mockSetEdges: vi.fn(),
  mockGetNode: vi.fn(),
  mockGetNodes: vi.fn(() => []),
  mockGetEdges: vi.fn(() => []),
  mockAddEdge: vi.fn(),
}));

vi.mock('reactflow', async () => {
  const actual = await vi.importActual('reactflow');
  return {
    ...actual,
    useReactFlow: () => ({
      setNodes: hoisted.mockSetNodes,
      setEdges: hoisted.mockSetEdges,
      getNode: hoisted.mockGetNode,
      getNodes: hoisted.mockGetNodes,
      getEdges: hoisted.mockGetEdges,
    }),
    addEdge: hoisted.mockAddEdge,
  };
});

describe('useAddStatus', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset default returns for getters
    hoisted.mockGetNodes.mockReturnValue([]);
    hoisted.mockGetEdges.mockReturnValue([]);
  });

  const mockStatusValues = {
    statusTemplate: { id: 'NEW_STATUS_ID', name: 'New Status', color: '#a1b6d8' },
    onEnter: [],
    onExit: [],
  };

  it('Case 1: should add a floating status node when no source/target exists', () => {
    // A node that is NOT a placeholder and has no connection logic
    const selectedNode: Node = {
      id: 'floating-btn',
      position: { x: 0, y: 0 },
      data: {},
      type: WorkflowNodeType.status,
    };

    const { result } = renderHook(() => useAddStatus(selectedNode));

    act(() => {
      result.current(mockStatusValues);
    });

    const updater = hoisted.mockSetNodes.mock.calls[0][0];
    const updatedNodes = updater([]);

    expect(updatedNodes).toContainEqual(expect.objectContaining({
      id: 'NEW_STATUS_ID',
      type: WorkflowNodeType.status,
    }));
  });

  it('Case 2: should append transition/status and REMOVE placeholder', () => {
    const parentNode: Node = { id: 'parent-1', position: { x: 0, y: 0 }, data: {} };

    // Simulate the placeholder node as created in your onNodeClick
    const placeholderNode = {
      id: 'placeholder-parent-1',
      type: WorkflowNodeType.placeholder,
      source: 'parent-1', // Crucial for your hook's logic
      position: { x: 100, y: 100 },
    } as PlaceholderNode;

    hoisted.mockGetNode.mockImplementation((id: string) => (id === 'parent-1' ? parentNode : null));

    const { result } = renderHook(() => useAddStatus(placeholderNode));

    act(() => {
      result.current(mockStatusValues);
    });

    // 1. Verify Nodes Logic
    const nodeUpdater = hoisted.mockSetNodes.mock.calls[0][0];
    // Start with the placeholder in the list
    const finalNodes = nodeUpdater([placeholderNode]);

    // Should filter out the placeholder and add 2 new nodes
    expect(finalNodes.find((n: Node) => n.id === placeholderNode.id)).toBeUndefined();
    expect(finalNodes).toHaveLength(2); // [Transition, Status]
    expect(finalNodes.find((n: Node) => n.type === WorkflowNodeType.transition)).toBeDefined();

    // 2. Verify Edges Logic
    const edgeUpdater = hoisted.mockSetEdges.mock.calls[0][0];
    const edges = edgeUpdater([]);
    expect(edges).toHaveLength(2);
    expect(edges[0].source).toBe('parent-1');
    expect(edges[1].target).toBe('NEW_STATUS_ID');
  });

  it('Case 3: should insert status/transition between two existing nodes via Edge click', () => {
    const sourceNode: Node = {
      id: 's1',
      type: WorkflowNodeType.status,
      position: { x: 0, y: 0 },
      data: {},
    };
    const targetNode: Node = {
      id: 't1',
      type: WorkflowNodeType.transition,
      position: { x: 500, y: 0 },
      data: {},
    };

    // A standard ReactFlow Edge
    const selectedEdge: Edge = { id: 'e-1', source: 's1', target: 't1' };

    hoisted.mockGetNode.mockImplementation((id: string) => {
      if (id === 's1') return sourceNode;
      if (id === 't1') return targetNode;
      return null;
    });

    const { result } = renderHook(() => useAddStatus(selectedEdge));

    act(() => {
      result.current(mockStatusValues);
    });

    // Verify Edges: Should delete the old one and add 3 new ones
    const edgeUpdater = hoisted.mockSetEdges.mock.calls[0][0];
    const currentEdges = [{ id: 'e-1', source: 's1', target: 't1' }];
    const finalEdges = edgeUpdater(currentEdges);

    expect(finalEdges.find((e: Edge) => e.id === 'e-1')).toBeUndefined();
    expect(finalEdges).toHaveLength(3);

    // Verify Nodes: Adds Transition and Status
    const nodeUpdater = hoisted.mockSetNodes.mock.calls[0][0];
    const finalNodes = nodeUpdater([]);
    expect(finalNodes).toHaveLength(2);
  });
});
