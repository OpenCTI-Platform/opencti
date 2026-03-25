import { renderHook } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Node, Edge } from 'reactflow';
import { usePlaceholdersSync } from './usePlaceholdersSync';
import { WorkflowNodeType } from '../utils';

const mockSetNodes = vi.fn();
const mockSetEdges = vi.fn();

vi.mock('reactflow', () => ({
  useReactFlow: () => ({
    setNodes: mockSetNodes,
    setEdges: mockSetEdges,
  }),
  MarkerType: {
    ArrowClosed: 'arrow-closed',
  },
}));

vi.mock('@mui/styles', () => ({
  useTheme: () => ({
    palette: {
      chip: { main: '#123456' },
    },
  }),
}));

describe('usePlaceholdersSync', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should create a placeholder for a status node with no outgoing transitions', () => {
    const statusNode: Node = {
      id: 'status-1',
      type: WorkflowNodeType.status,
      position: { x: 0, y: 0 },
      data: {},
    };

    const initialNodes: Node[] = [statusNode];
    const initialEdges: Edge[] = [];

    renderHook(({ nodes, edges }) => usePlaceholdersSync(nodes, edges), {
      initialProps: { nodes: initialNodes, edges: initialEdges },
    });

    // Verify setNodes was called to add the placeholder
    expect(mockSetNodes).toHaveBeenCalledWith(expect.any(Function));
    const nodeUpdater = mockSetNodes.mock.calls[0][0] as (nds: Node[]) => Node[];
    const resultNodes = nodeUpdater(initialNodes);

    expect(resultNodes).toHaveLength(2);
    expect(resultNodes.find((n) => n.type === WorkflowNodeType.placeholder)).toBeDefined();

    // Verify setEdges was called to link the status to the placeholder
    expect(mockSetEdges).toHaveBeenCalledWith(expect.any(Function));
    const edgeUpdater = mockSetEdges.mock.calls[0][0] as (eds: Edge[]) => Edge[];
    const resultEdges = edgeUpdater(initialEdges);

    expect(resultEdges).toHaveLength(1);
    expect(resultEdges[0].source).toBe('status-1');
    expect(resultEdges[0].target).toBe(`${WorkflowNodeType.placeholder}-status-1`);
    expect(resultEdges[0].style?.stroke).toBe('#123456'); // Verified theme usage
  });

  it('should not create a placeholder if the status already has an outgoing transition', () => {
    const nodes: Node[] = [
      { id: 'status-1', type: WorkflowNodeType.status, position: { x: 0, y: 0 }, data: {} },
      { id: 'trans-1', type: WorkflowNodeType.transition, position: { x: 10, y: 10 }, data: {} },
    ];
    const edges: Edge[] = [
      { id: 'e1', source: 'status-1', target: 'trans-1' },
    ];

    renderHook(({ nodes, edges }) => usePlaceholdersSync(nodes, edges), {
      initialProps: { nodes, edges },
    });

    // Should not call setNodes because no placeholders are required
    expect(mockSetNodes).not.toHaveBeenCalled();
  });

  it('should remove existing placeholders if they are no longer needed', () => {
    // Current state has a placeholder
    const nodes: Node[] = [
      { id: 'status-1', type: WorkflowNodeType.status, position: { x: 0, y: 0 }, data: {} },
      { id: 'trans-1', type: WorkflowNodeType.transition, position: { x: 10, y: 10 }, data: {} },
      { id: 'placeholder-status-1', type: WorkflowNodeType.placeholder, position: { x: 0, y: 0 }, data: {} },
    ];
    // status-1 now has a real transition, making the placeholder obsolete
    const edges: Edge[] = [
      { id: 'e-real', source: 'status-1', target: 'trans-1' },
      { id: 'e-placeholder', source: 'status-1', target: 'placeholder-status-1', type: WorkflowNodeType.placeholder },
    ];

    renderHook(({ nodes, edges }) => usePlaceholdersSync(nodes, edges), {
      initialProps: { nodes, edges },
    });

    // Verify setNodes filters out the placeholder
    const nodeUpdater = mockSetNodes.mock.calls[0][0] as (nds: Node[]) => Node[];
    const resultNodes = nodeUpdater(nodes);
    expect(resultNodes.filter((n) => n.type === WorkflowNodeType.placeholder)).toHaveLength(0);

    // Verify setEdges filters out the placeholder edge
    const edgeUpdater = mockSetEdges.mock.calls[0][0] as (eds: Edge[]) => Edge[];
    const resultEdges = edgeUpdater(edges);
    expect(resultEdges).toHaveLength(1);
    expect(resultEdges[0].id).toBe('e-real');
  });

  it('should avoid infinite updates if placeholders are already correctly synced', () => {
    const nodes: Node[] = [
      { id: 'status-1', type: WorkflowNodeType.status, position: { x: 0, y: 0 }, data: {} },
      { id: 'placeholder-status-1', type: WorkflowNodeType.placeholder, position: { x: 0, y: 0 }, data: {} },
    ];
    const edges: Edge[] = [
      { id: 'e-placeholder-status-1', source: 'status-1', target: 'placeholder-status-1', type: WorkflowNodeType.placeholder },
    ];

    renderHook(({ nodes, edges }) => usePlaceholdersSync(nodes, edges), {
      initialProps: { nodes, edges },
    });

    // hasChanged logic should prevent these from being called
    expect(mockSetNodes).not.toHaveBeenCalled();
    expect(mockSetEdges).not.toHaveBeenCalled();
  });
});
