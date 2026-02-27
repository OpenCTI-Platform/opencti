import type { Node, Edge } from 'reactflow';
import { SubTypeWorkflowQuery$data } from '../__generated__/SubTypeWorkflowQuery.graphql';
import { AuthorizedMemberOption } from '../../../../../utils/authorizedMembers';

export type Condition = { field: string; operator: string; value: string }
  | { type: string };

export type Action = {
  type: string;
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

export const NODE_SIZE = { width: 160, height: 50 };

const formatActions = (actions: Action[]) => {
  return actions.map(({ type, params }) => {
    if (type === 'updateAuthorizedMembers') {
      return {
        type,
        mode: 'sync',
        params: { authorized_members: (params as { authorized_members: AuthorizedMemberOption[] }).authorized_members
          .map(({ value, accessRight }) => ({ id: value, access_right: accessRight })) },
      };
    }
  });
};

const transformToWorkflowDefinition = (nodes: Node[], edges: Edge[], workflowDefinition: SubTypeWorkflowQuery$data['workflowDefinition']) => {
  // 1. Extract States
  const states = nodes
    .filter((node) => node.type === 'status')
    .map(({ id, data: { onEnter = [], onExit = [] } }) => {
      return {
        statusId: id,
        onEnter: formatActions(onEnter),
        onExit: formatActions(onExit),
      };
    });

  // 2. Extract Transitions
  const transitions = nodes
    .filter((node) => node.type === 'transition')
    .map(({ id, data: { event, conditions = [], actions = [] } }) => {
      const targetEdge = edges.find((e) => e.target === id);
      const sourceEdge = edges.find((e) => e.source === id);

      return {
        from: targetEdge?.source || '',
        to: sourceEdge?.target || '',
        event: event,
        conditions: conditions,
        actions: formatActions(actions),
      };
    });

  // 3. Get first status
  const initialState = nodes
    .filter((node) => node.type === 'status')
    .find(({ id }) => !edges.find((e) => e.target === id));

  return {
    id: workflowDefinition?.id,
    name: workflowDefinition?.name,
    initialState: initialState?.id || workflowDefinition?.initialState,
    states,
    transitions,
  };
};

export {
  transformToWorkflowDefinition,
};
