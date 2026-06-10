import { describe, it, expect } from 'vitest';
import { transformToWorkflowDefinition, isElementStatus, isNewElementStatus, WorkflowNodeType, WorkflowActionType } from './utils';
import type { Node, Edge } from 'reactflow';
import { SubTypeWorkflowQuery$data } from '../__generated__/SubTypeWorkflowQuery.graphql';

describe('Workflow utils', () => {
  const mockWorkflowDefinition = {
    id: '1234',
    name: 'Test Workflow',
    initialState: 'state-1',
  } as SubTypeWorkflowQuery$data['workflowDefinition'];

  it('should transform an empty graph', () => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const result = transformToWorkflowDefinition(nodes, edges, mockWorkflowDefinition);
    expect(result).toEqual({
      id: '1234',
      name: 'Test Workflow',
      initialState: 'state-1',
      states: [],
      transitions: [],
    });
  });

  it('should identify an initial state', () => {
    const nodes: Node[] = [
      { id: 'state-1', type: WorkflowNodeType.status, data: { statusTemplate: { id: 'state-1', name: 'State 1', color: '#ffffff' } }, position: { x: 0, y: 0 } },
      { id: 'state-2', type: WorkflowNodeType.status, data: { statusTemplate: { id: 'state-2', name: 'State 2', color: '#ffffff' } }, position: { x: 0, y: 0 } },
    ];
    const edges: Edge[] = [
      { id: 'e1-2', source: 'state-1', target: 'state-2', type: 'smoothstep' },
    ];
    const result = transformToWorkflowDefinition(nodes, edges, mockWorkflowDefinition);
    expect(result.initialState).toBe('state-1');
  });

  it('should transform a simple graph with states and transitions', () => {
    const nodes: Node[] = [
      { id: 'state-1', type: WorkflowNodeType.status, data: { statusTemplate: { id: 'state-1', name: 'State 1', color: '#ffffff' }, onEnter: [], onExit: [] }, position: { x: 0, y: 0 } },
      { id: 'trans-1', type: WorkflowNodeType.transition, data: { event: 'start' }, position: { x: 0, y: 0 } },
      { id: 'state-2', type: WorkflowNodeType.status, data: { statusTemplate: { id: 'state-2', name: 'State 2', color: '#ffffff' }, onEnter: [], onExit: [] }, position: { x: 0, y: 0 } },
    ];
    const edges: Edge[] = [
      { id: 'e1', source: 'state-1', target: 'trans-1', type: 'smoothstep' },
      { id: 'e2', source: 'trans-1', target: 'state-2', type: 'smoothstep' },
    ];
    const result = transformToWorkflowDefinition(nodes, edges, mockWorkflowDefinition);
    expect(result.states.length).toBe(2);
    expect(result.transitions.length).toBe(1);
    expect(result.transitions[0]).toEqual({
      from: 'state-1',
      to: 'state-2',
      event: 'start',
      comment: undefined,
      conditions: {},
      asyncActions: [],
      syncActions: [],
    });
  });

  it('should handle transitions with no target', () => {
    const nodes: Node[] = [
      { id: 'state-1', type: WorkflowNodeType.status, data: { statusTemplate: { id: 'state-1', name: 'State 1', color: '#ffffff' }, onEnter: [], onExit: [] }, position: { x: 0, y: 0 } },
      { id: 'trans-1', type: WorkflowNodeType.transition, data: { event: 'end' }, position: { x: 0, y: 0 } },
    ];
    const edges: Edge[] = [
      { id: 'e1', source: 'state-1', target: 'trans-1', type: 'smoothstep' },
    ];
    const result = transformToWorkflowDefinition(nodes, edges, mockWorkflowDefinition);
    expect(result.transitions.length).toBe(1);
    expect(result.transitions[0]).toEqual({
      from: 'state-1',
      to: null,
      event: 'end',
      comment: undefined,
      conditions: {},
      asyncActions: [],
      syncActions: [],
    });
  });

  it('should format actions correctly', () => {
    const nodes: Node[] = [
      {
        id: 'state-1',
        type: WorkflowNodeType.status,
        data: {
          statusTemplate: { id: 'state-1', name: 'State 1', color: '#ffffff' },
          onEnter: [
            {
              type: WorkflowActionType.updateAuthorizedMembers,
              params: { authorized_members: [{ value: 'user-1', accessRight: 'edit', groupsRestriction: [{ value: 'group-1' }] }] },
            },
          ],
          onExit: [{ type: WorkflowActionType.validateDraft }],
        },
        position: { x: 0, y: 0 },
      },
    ];
    const result = transformToWorkflowDefinition(nodes, [], mockWorkflowDefinition);
    expect(result.states[0].onEnter).toEqual([
      {
        type: 'updateAuthorizedMembers',
        params: { authorized_members: [{ id: 'user-1', access_right: 'edit', groups_restriction_ids: ['group-1'] }] },
      },
    ]);
    expect(result.states[0].onExit).toEqual([{ type: 'validateDraft' }]);
  });

  it('should fan out multiple-source transitions into one entry per source state', () => {
    const nodes: Node[] = [
      { id: 'state-1', type: WorkflowNodeType.status, data: { statusTemplate: { id: 'state-1' }, onEnter: [], onExit: [] }, position: { x: 0, y: 0 } },
      { id: 'state-2', type: WorkflowNodeType.status, data: { statusTemplate: { id: 'state-2' }, onEnter: [], onExit: [] }, position: { x: 0, y: 0 } },
      { id: 'state-reject', type: WorkflowNodeType.status, data: { statusTemplate: { id: 'state-reject' }, onEnter: [], onExit: [] }, position: { x: 0, y: 0 } },
      { id: 'trans-reject', type: WorkflowNodeType.transition, data: { event: 'reject', conditions: {}, actions: [], asyncActions: [], syncActions: [] }, position: { x: 0, y: 0 } },
    ];
    const edges: Edge[] = [
      // Both state-1 and state-2 feed into the same "reject" transition node
      { id: 'e1', source: 'state-1', target: 'trans-reject', type: 'smoothstep' },
      { id: 'e2', source: 'state-2', target: 'trans-reject', type: 'smoothstep' },
      { id: 'e3', source: 'trans-reject', target: 'state-reject', type: 'smoothstep' },
    ];
    const result = transformToWorkflowDefinition(nodes, edges, mockWorkflowDefinition);
    // Must produce two separate transitions rather than one with from: ['state-1', 'state-2']
    expect(result.transitions).toHaveLength(2);
    expect(result.transitions).toEqual(expect.arrayContaining([
      expect.objectContaining({ from: 'state-1', to: 'state-reject', event: 'reject' }),
      expect.objectContaining({ from: 'state-2', to: 'state-reject', event: 'reject' }),
    ]));
  });

  it('should correctly identify element types', () => {
    const statusNode: Node = { id: '1', type: WorkflowNodeType.status, data: {}, position: { x: 0, y: 0 } };
    const placeholderNode: Node = { id: '2', type: WorkflowNodeType.placeholder, data: {}, position: { x: 0, y: 0 } };
    const transitionNode: Node = { id: '3', type: WorkflowNodeType.transition, data: {}, position: { x: 0, y: 0 } };

    expect(isElementStatus(statusNode)).toBe(true);
    expect(isElementStatus(placeholderNode)).toBe(true);
    expect(isElementStatus(transitionNode)).toBe(false);

    expect(isNewElementStatus(statusNode)).toBe(false);
    expect(isNewElementStatus(placeholderNode)).toBe(true);
    expect(isNewElementStatus(transitionNode)).toBe(false);
  });
});
