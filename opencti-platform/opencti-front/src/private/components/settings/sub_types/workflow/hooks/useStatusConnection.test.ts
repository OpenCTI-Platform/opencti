import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Connection, Node, Edge, MarkerType } from 'reactflow';
import { useStatusConnection } from './useStatusConnection';
import { WorkflowNodeType } from '../utils';

const hoisted = vi.hoisted(() => ({
  mockSetNodes: vi.fn(),
  mockSetEdges: vi.fn(),
  mockGetNode: vi.fn<(id: string) => Node | undefined>(),
  mockGetEdges: vi.fn(() => []),
  mockAddEdge: vi.fn((params: Edge | Connection, eds: Edge[]) => [...eds, params as Edge]),
}));

vi.mock('reactflow', async () => {
  const actual = await vi.importActual('reactflow');
  return {
    ...actual,
    useReactFlow: () => ({
      setNodes: hoisted.mockSetNodes,
      setEdges: hoisted.mockSetEdges,
      getNode: hoisted.mockGetNode,
      getEdges: hoisted.mockGetEdges,
    }),
    addEdge: hoisted.mockAddEdge,
  };
});

vi.mock('@mui/styles', () => ({
  useTheme: () => ({
    palette: {
      chip: { main: '#ff5722' },
    },
  }),
}));

describe('useStatusConnection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    hoisted.mockGetEdges.mockReturnValue([]);
    vi.useFakeTimers().setSystemTime(new Date('2026-03-17'));
  });

  // Cases 1 & 2 omitted for brevity as they passed, but they should use hoisted.mockSetNodes

  it('Case 3: Status -> Transition (should use addEdge helper)', () => {
    const sourceNode: Node = { id: 's1', type: WorkflowNodeType.status, position: { x: 0, y: 0 }, data: {} };
    const targetNode: Node = { id: 't1', type: WorkflowNodeType.transition, position: { x: 100, y: 0 }, data: {} };

    hoisted.mockGetNode.mockImplementation((id: string) => (id === 's1' ? sourceNode : targetNode));

    const { result } = renderHook(() => useStatusConnection());
    const connection: Connection = { source: 's1', target: 't1', sourceHandle: null, targetHandle: null };

    act(() => {
      result.current(connection);
    });

    // 2. Extract the functional updater passed to setEdges
    expect(hoisted.mockSetEdges).toHaveBeenCalled();
    const edgeUpdater = hoisted.mockSetEdges.mock.calls[0][0] as (eds: Edge[]) => Edge[];

    // 3. Manually execute the updater to trigger the addEdge call
    edgeUpdater([]);

    expect(hoisted.mockAddEdge).toHaveBeenCalledWith(
      expect.objectContaining({
        source: 's1',
        target: 't1',
        type: WorkflowNodeType.transition,
      }),
      expect.any(Array),
    );
  });

  it('Case 4: Transition -> Status (should include markerEnd arrow)', () => {
    const sourceNode: Node = { id: 't1', type: WorkflowNodeType.transition, position: { x: 0, y: 0 }, data: {} };
    const targetNode: Node = { id: 's1', type: WorkflowNodeType.status, position: { x: 100, y: 0 }, data: {} };

    hoisted.mockGetNode.mockImplementation((id: string) => (id === 't1' ? sourceNode : targetNode));

    const { result } = renderHook(() => useStatusConnection());
    const connection: Connection = { source: 't1', target: 's1', sourceHandle: null, targetHandle: null };

    act(() => {
      result.current(connection);
    });

    // Extract and execute the updater
    const edgeUpdater = hoisted.mockSetEdges.mock.calls[0][0] as (eds: Edge[]) => Edge[];
    edgeUpdater([]);

    expect(hoisted.mockAddEdge).toHaveBeenCalledWith(
      expect.objectContaining({
        markerEnd: { type: MarkerType.ArrowClosed, color: '#ff5722' },
      }),
      expect.any(Array),
    );
  });
});
