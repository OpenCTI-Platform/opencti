import type { Node, Edge } from 'reactflow';
import { SubTypeWorkflowQuery$data, WorkflowActionMode } from '../__generated__/SubTypeWorkflowQuery.graphql';
import { AuthorizedMemberOption } from '../../../../../utils/authorizedMembers';
import type { FilterGroup } from '../../../../../utils/filters/filtersHelpers-types';

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
  asyncActions?: Action[];
  syncActions?: Action[];
  conditions?: { filters: FilterGroup };
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
  shareWithOrganizations = 'shareWithOrganizations',
  unshareFromOrganizations = 'unshareFromOrganizations',
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
    if (type === 'shareWithOrganizations') {
      const orgIds = ((params as any)?.organizations ?? []).map((o: any) => (typeof o === 'string' ? o : o.value));
      return {
        type: 'asyncBulkAction',
        mode: 'async' as const,
        params: {
          scope: 'KNOWLEDGE',
          actions: [{ type: 'SHARE', context: { values: orgIds } }],
          failOnAnyError: true,
        },
      };
    }
    if (type === 'unshareFromOrganizations') {
      const orgIds = ((params as any)?.organizations ?? []).map((o: any) => (typeof o === 'string' ? o : o.value));
      return {
        type: 'asyncBulkAction',
        mode: 'async' as const,
        params: {
          scope: 'KNOWLEDGE',
          actions: [{ type: 'UNSHARE', context: { values: orgIds } }],
          failOnAnyError: true,
        },
      };
    }
    return undefined;
  }).filter(Boolean);
};

const transformToWorkflowDefinition = (
  nodes: Node[],
  edges: Edge[],
  workflowDefinition: SubTypeWorkflowQuery$data['workflowDefinition'],
) => {
  // 1. Extract States
  const states = nodes.flatMap(({ type, data: { onEnter = [], onExit = [], statusTemplate } }) => {
    if (type === WorkflowNodeType.status) {
      return [{
        statusId: statusTemplate.id,
        onEnter: formatActions(onEnter),
        onExit: formatActions(onExit),
      }];
    }
    return [];
  });

  // 2. Extract transitions
  const transitions = nodes.flatMap((node) => {
    if (node.type === WorkflowNodeType.transition) {
      const { event, conditions = {}, actions = [], asyncActions = [], syncActions = [] } = node.data;

      // requiresOrganizationInput is true when a share/unshare action has no pre-filled orgs
      const requiresOrganizationInput = asyncActions.some((a: Action) =>
        (a.type === WorkflowActionType.shareWithOrganizations || a.type === WorkflowActionType.unshareFromOrganizations)
        && !((a.params as any)?.organizations?.length),
      );

      // Find ALL incoming edges (From Status -> This Transition)
      const incomingEdges = edges.filter((e) => e.target === node.id);
      // Find ALL outgoing edges (This Transition -> To Status)
      const outgoingEdges = edges.filter((e) => e.source === node.id);

      // Create a transition entry for every possible path through this node
      // This handles: Multiple Sources -> 1 Transition -> Multiple Targets
      if (outgoingEdges.length > 0) {
        return incomingEdges.flatMap((inEdge) =>
          outgoingEdges.map((outEdge) => ({
            from: nodes.find((n) => n.id === inEdge.source)?.data.statusTemplate.id,
            to: nodes.find((n) => n.id === outEdge.target)?.data.statusTemplate.id || null,
            event,
            conditions,
            actions: formatActions(actions),
            asyncActions: formatActions(asyncActions),
            syncActions: formatActions(syncActions),
            requiresOrganizationInput,
          })),
        );
      }
      // Multiple Sources -> 1 Transition -> (no target)
      return incomingEdges.map((inEdge) => ({
        from: nodes.find((n) => n.id === inEdge.source)?.data.statusTemplate.id,
        to: null as string | null,
        event,
        conditions,
        actions: formatActions(actions),
        asyncActions: formatActions(asyncActions),
        syncActions: formatActions(syncActions),
        requiresOrganizationInput,
      }));
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
    initialState: nodes.find((n) => n.id === initialState?.id)?.data.statusTemplate.id || workflowDefinition?.initialState,
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
