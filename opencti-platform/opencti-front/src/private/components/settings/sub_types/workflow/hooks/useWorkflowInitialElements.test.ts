import { renderHook } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MarkerType, Node } from 'reactflow';
import { useWorkflowInitialElements } from './useWorkflowInitialElements';
import { WorkflowNodeType } from '../utils';
import { SubTypeWorkflowQuery$data } from '../../__generated__/SubTypeWorkflowQuery.graphql';

vi.mock('@mui/styles', () => ({
  useTheme: () => ({
    palette: {
      chip: { main: '#00bcd4' },
    },
  }),
}));

vi.mock('../../../../../../utils/authorizedMembers', () => ({
  authorizedMembersToOptions: vi.fn((members: unknown) => members),
}));

vi.mock('../../../../../../utils/connection', () => ({
  getNodes: <T>(connection: { edges?: ReadonlyArray<{ node: T } | null> | null }): T[] => {
    return (connection?.edges ?? [])
      .map((edge) => edge?.node)
      .filter((node): node is T => node !== null && node !== undefined);
  },
}));

describe('useWorkflowInitialElements', () => {
  // 1. Strictly Typed Mock Data
  const mockStatusTemplates: SubTypeWorkflowQuery$data['statusTemplates'] = {
    edges: [
      { node: { id: 'status-open', name: 'Open', color: 'blue' } },
      { node: { id: 'status-closed', name: 'Closed', color: 'red' } },
    ],
  };

  const mockMembers: SubTypeWorkflowQuery$data['members'] = {
    edges: [
      { node: { id: 'user-1', name: 'John Doe', entity_type: 'User' } },
    ],
  };

  const mockWorkflowDefinition: SubTypeWorkflowQuery$data['workflowDefinition'] = {
    id: 'workflow-1',
    name: 'Sample Workflow',
    initialState: 'status-open',
    states: [
      {
        statusId: 'status-open',
        onEnter: [
          {
            type: 'updateAuthorizedMembers',
            params: {
              authorized_members: [
                { id: 'user-1', name: 'John Doe', entity_type: 'User', access_right: 'admin' },
              ],
            },
            mode: 'sync',
          },
        ],
        onExit: [],
      },
    ],
    transitions: [
      {
        from: 'status-open',
        to: 'status-closed',
        event: 'close_event',
        conditions: {},
        actions: [],
      },
    ],
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should return empty arrays if workflowDefinition is null', () => {
    const { result } = renderHook(() =>
      useWorkflowInitialElements(null, null, null),
    );

    expect(result.current.initialNodes).toEqual([]);
    expect(result.current.initialEdges).toEqual([]);
  });

  it('should transform states into status nodes', () => {
    const { result } = renderHook(() =>
      useWorkflowInitialElements(mockWorkflowDefinition, mockStatusTemplates, mockMembers),
    );

    const statusNodes = result.current.initialNodes.filter(
      (n: Node): n is Node => n.type === WorkflowNodeType.status,
    );

    expect(statusNodes).toHaveLength(1);
    expect(statusNodes[0]).toMatchObject({
      id: 'status-open',
      type: WorkflowNodeType.status,
    });

    expect(statusNodes[0].data.statusTemplate).toEqual({
      id: 'status-open',
      name: 'Open',
      color: 'blue',
    });
  });

  it('should transform transitions into one node and two edges', () => {
    const { result } = renderHook(() =>
      useWorkflowInitialElements(mockWorkflowDefinition, mockStatusTemplates, mockMembers),
    );

    const transitionNodes = result.current.initialNodes.filter(
      (n: Node): n is Node => n.type === WorkflowNodeType.transition,
    );
    const transitionEdges = result.current.initialEdges;

    expect(transitionNodes).toHaveLength(1);
    expect(transitionNodes[0].id).toBe(`${WorkflowNodeType.transition}-status-open-status-closed`);

    expect(transitionEdges).toHaveLength(2);
    expect(transitionEdges[0].source).toBe('status-open');
    expect(transitionEdges[1].markerEnd).toEqual({
      type: MarkerType.ArrowClosed,
      color: '#00bcd4',
    });
  });

  it('should enrich authorized members actions with member data', () => {
    const { result } = renderHook(() =>
      useWorkflowInitialElements(mockWorkflowDefinition, mockStatusTemplates, mockMembers),
    );

    const node = result.current.initialNodes.find((n: Node) => n.id === 'status-open');
    // Accessing typed data property
    const action = node?.data.onEnter[0];

    expect(action.type).toBe('updateAuthorizedMembers');
    expect(action.params.authorized_members[0]).toMatchObject({
      id: 'user-1',
      name: 'John Doe',
      access_right: 'admin',
    });
  });

  it('should recompute only when workflowDefinition changes', () => {
    interface HookProps {
      def: SubTypeWorkflowQuery$data['workflowDefinition'];
    }

    const { result, rerender } = renderHook(
      ({ def }: HookProps) =>
        useWorkflowInitialElements(def, mockStatusTemplates, mockMembers),
      { initialProps: { def: mockWorkflowDefinition } },
    );

    const firstResult = result.current;

    rerender({ def: mockWorkflowDefinition });
    expect(result.current).toBe(firstResult);

    const newDef: SubTypeWorkflowQuery$data['workflowDefinition'] = {
      ...mockWorkflowDefinition,
      states: [],
    };
    rerender({ def: newDef });
    expect(result.current).not.toBe(firstResult);
  });
});
