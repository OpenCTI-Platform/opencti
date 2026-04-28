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
      { id: 'state-1', type: WorkflowNodeType.status, data: {}, position: { x: 0, y: 0 } },
      { id: 'state-2', type: WorkflowNodeType.status, data: {}, position: { x: 0, y: 0 } },
    ];
    const edges: Edge[] = [
      { id: 'e1-2', source: 'state-1', target: 'state-2', type: 'smoothstep' },
    ];
    const result = transformToWorkflowDefinition(nodes, edges, mockWorkflowDefinition);
    expect(result.initialState).toBe('state-1');
  });

  it('should transform a simple graph with states and transitions', () => {
    const nodes: Node[] = [
      { id: 'state-1', type: WorkflowNodeType.status, data: { onEnter: [], onExit: [] }, position: { x: 0, y: 0 } },
      { id: 'trans-1', type: WorkflowNodeType.transition, data: { event: 'start' }, position: { x: 0, y: 0 } },
      { id: 'state-2', type: WorkflowNodeType.status, data: { onEnter: [], onExit: [] }, position: { x: 0, y: 0 } },
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
      conditions: {},
      actions: [],
    });
  });

  it('should handle transitions with no target', () => {
    const nodes: Node[] = [
      { id: 'state-1', type: WorkflowNodeType.status, data: { onEnter: [], onExit: [] }, position: { x: 0, y: 0 } },
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
      conditions: {},
      actions: [],
    });
  });

  it('should format actions correctly', () => {
    const nodes: Node[] = [
      {
        id: 'state-1',
        type: WorkflowNodeType.status,
        data: {
          onEnter: [
            {
              type: WorkflowActionType.updateAuthorizedMembers,
              params: { authorized_members: [{ value: 'user-1', accessRight: 'edit' }] },
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
        mode: 'sync',
        params: { authorized_members: [{ id: 'user-1', access_right: 'edit' }] },
      },
    ]);
    expect(result.states[0].onExit).toEqual([{ type: 'validateDraft', mode: 'sync' }]);
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
