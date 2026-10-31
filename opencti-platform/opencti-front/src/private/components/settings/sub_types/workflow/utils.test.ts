import { describe, it, expect } from 'vitest';
import { transformToWorkflowDefinition, isElementStatus, isNewElementStatus, WorkflowNodeType, WorkflowActionType, findTargetStatusExits } from './utils';
import type { Node, Edge } from 'reactflow';
import { SubTypeWorkflowQuery$data } from '../__generated__/SubTypeWorkflowQuery.graphql';

describe('Workflow utils', () => {
  const mockWorkflowDefinition = {
    id: '1234',
    name: 'Test Workflow',
    initialState: 'state-1',
  } as SubTypeWorkflowQuery$data['workflowDefinition'];

  it('should transform an empty graph without inheriting the server initialState', () => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const result = transformToWorkflowDefinition(nodes, edges, mockWorkflowDefinition);
    expect(result).toEqual({
      id: '1234',
      name: 'Test Workflow',
      initialState: '*',
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

  describe('initial state after an edit', () => {
    const status = (id: string): Node => ({ id, type: WorkflowNodeType.status, data: { statusTemplate: { id, name: id, color: '#ffffff' } }, position: { x: 0, y: 0 } });
    const transition = (id: string): Node => ({ id, type: WorkflowNodeType.transition, data: { event: id }, position: { x: 0, y: 0 } });
    const link = (source: string, target: string): Edge => ({ id: `e-${source}->${target}`, source, target, type: WorkflowNodeType.transition });
    const definition = { ...mockWorkflowDefinition, initialState: 'NEW' } as SubTypeWorkflowQuery$data['workflowDefinition'];
    // NEW -submit-> IN_REVIEW, IN_REVIEW -reject-> NEW, IN_REVIEW -approve-> ANALYZED: every status has an incoming edge.
    const nodes = [status('NEW'), status('IN_REVIEW'), status('ANALYZED'), transition('submit'), transition('reject'), transition('approve')];
    const edges = [link('NEW', 'submit'), link('submit', 'IN_REVIEW'), link('IN_REVIEW', 'reject'), link('reject', 'NEW'), link('IN_REVIEW', 'approve'), link('approve', 'ANALYZED')];

    it('keeps the saved initial state while no status is a root', () => {
      expect(transformToWorkflowDefinition(nodes, edges, definition).initialState).toBe('NEW');
    });

    it('takes the only root, as the backend requires (ROOT_STATE_MISMATCH)', () => {
      // approve -> ANALYZED deleted: ANALYZED is the only status without an incoming edge.
      expect(transformToWorkflowDefinition(nodes, edges.filter((e) => e.target !== 'ANALYZED'), definition).initialState).toBe('ANALYZED');
      // DRAFT connected in front of NEW in a graph where NEW was the root.
      const front = [status('DRAFT'), transition('start'), status('NEW'), transition('analyze'), status('ANALYZED')];
      const frontEdges = [link('DRAFT', 'start'), link('start', 'NEW'), link('NEW', 'analyze'), link('analyze', 'ANALYZED')];
      expect(transformToWorkflowDefinition(front, frontEdges, definition).initialState).toBe('DRAFT');
    });

    it('keeps the saved initial state when it is one of several roots', () => {
      const twoRoots = [status('DRAFT'), status('NEW'), transition('analyze'), status('ANALYZED')];
      expect(transformToWorkflowDefinition(twoRoots, [link('NEW', 'analyze'), link('analyze', 'ANALYZED')], definition).initialState).toBe('NEW');
    });

    it('falls back to the first status without an incoming edge once the saved one is gone', () => {
      const withoutNew = nodes.filter((n) => n.id !== 'NEW');
      const result = transformToWorkflowDefinition(withoutNew, edges.filter((e) => e.source !== 'NEW' && e.target !== 'NEW' && e.target !== 'ANALYZED'), definition);
      // IN_REVIEW still has an incoming edge (from submit); ANALYZED is the first status without one.
      expect(result.initialState).toBe('ANALYZED');
    });
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

describe('findTargetStatusExits', () => {
  const status = (id: string, name: string) => ({ id, type: WorkflowNodeType.status, data: { statusTemplate: { id, name, color: '' } }, position: { x: 0, y: 0 } }) as Node;
  const transition = (id: string, event: string) => ({ id, type: WorkflowNodeType.transition, data: { event }, position: { x: 0, y: 0 } }) as Node;
  const edge = (source: string, target: string) => ({ id: `${source}->${target}`, source, target }) as Edge;
  const nodes = [status('open', 'Open'), status('closed', 'Closed'), transition('t-close', 'close'), transition('t-reopen', 'reopen'),
    { id: 'placeholder-open', type: WorkflowNodeType.placeholder, data: {}, position: { x: 0, y: 0 } } as Node];

  it('returns nothing for a transition into a final status', () => {
    const edges = [edge('open', 't-close'), edge('t-close', 'closed'), edge('closed', 'placeholder-closed')];
    expect(findTargetStatusExits('t-close', nodes, edges)).toBeUndefined();
  });

  it('names the target status and the transitions that leave it', () => {
    const edges = [edge('open', 't-close'), edge('t-close', 'closed'), edge('closed', 't-reopen'), edge('t-reopen', 'open')];
    expect(findTargetStatusExits('t-close', nodes, edges)).toEqual({ status: 'Closed', events: ['reopen'] });
  });

  it('returns nothing for a transition without a target status', () => {
    expect(findTargetStatusExits('t-close', nodes, [edge('open', 't-close')])).toBeUndefined();
  });
});
