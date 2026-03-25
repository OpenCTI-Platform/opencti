import type { Node, Edge } from 'reactflow';
import { SubTypeWorkflowQuery$data, WorkflowActionMode } from '../__generated__/SubTypeWorkflowQuery.graphql';
import { AuthorizedMemberOption } from '../../../../../utils/authorizedMembers';

export type Condition = { field: string; operator: string; value: string }
  | { type: string };

export type Action = {
  type: string;
  mode?: WorkflowActionMode;
  params?: unknown;
};

export type Status = {
  statusTemplate: { id: string; name: string; color: string };
  color?: string;
  onEnter?: Action[];
  onExit?: Action[];
};

export type Transition = {
  event: string;
  actions?: Action[];
  conditions?: Condition[];
};

export const NEW_EVENT_NAME = 'NEW_EVENT';

export const NEW_STATUS_NAME = 'NEW_STATUS';

export enum WorkflowNodeType {
  status = 'status',
  transition = 'transition',
  placeholder = 'placeholder',
}

export enum WorkflowDataType {
  // Actions
  actions = 'actions',
  onEnter = 'onEnter',
  onExit = 'onExit',
  // Conditions
  conditions = 'conditions',
}

export enum WorkflowActionType {
  updateAuthorizedMembers = 'updateAuthorizedMembers',
  validateDraft = 'validateDraft',
}

export const NODE_SIZE = { width: 160, height: 50 };

const formatActions = (actions: Action[] = []) => {
  return actions.map(({ type, params, mode = 'sync' }) => {
    if (type === 'updateAuthorizedMembers') {
      return {
        type,
        mode,
        params: { authorized_members: (params as { authorized_members: AuthorizedMemberOption[] }).authorized_members
          .map(({ value, accessRight }) => ({ id: value, access_right: accessRight })) },
      };
    }
    if (type === 'validateDraft') {
      return {
        type,
        mode,
      };
    }
  });
};

const transformToWorkflowDefinition = (
  nodes: Node[],
  edges: Edge[],
  workflowDefinition: SubTypeWorkflowQuery$data['workflowDefinition'],
) => {
  // 1. Extract States
  const states = nodes.flatMap(({ id, type, data: { onEnter = [], onExit = [] } }) => {
    if (type === WorkflowNodeType.status) {
      return [{
        statusId: id,
        onEnter: formatActions(onEnter),
        onExit: formatActions(onExit),
      }];
    }
    return [];
  });

  // 2. Extract transitions
  const transitions = nodes.flatMap((node) => {
    if (node.type === WorkflowNodeType.transition) {
      const { event, conditions = [], actions = [] } = node.data;

      // Find ALL incoming edges (From Status -> This Transition)
      const incomingEdges = edges.filter((e) => e.target === node.id);
      // Find ALL outgoing edges (This Transition -> To Status)
      const outgoingEdges = edges.filter((e) => e.source === node.id);

      // Create a transition entry for every possible path through this node
      // This handles: Multiple Sources -> 1 Transition -> Multiple Targets
      return incomingEdges.flatMap((inEdge) =>
        outgoingEdges.map((outEdge) => ({
          from: inEdge.source,
          to: outEdge.target,
          event,
          conditions,
          actions: formatActions(actions),
        })),
      );
    }
    return [];
  });

  // 3. Identify Initial State
  const initialState = nodes
    .filter((node) => node.type === WorkflowNodeType.status)
    .find(({ id }) => !edges.find((e) => e.target === id));

  return {
    id: workflowDefinition?.id,
    name: workflowDefinition?.name,
    initialState: initialState?.id || workflowDefinition?.initialState,
    states,
    transitions,
  };
};

const isElementStatus = (selectedElement: Node) => (selectedElement?.type === WorkflowNodeType.status || selectedElement?.type === WorkflowNodeType.placeholder);
const isNewElementStatus = (selectedElement: Node) => (selectedElement?.type === WorkflowNodeType.placeholder);

export {
  transformToWorkflowDefinition,
  isElementStatus,
  isNewElementStatus,
};
