import type { Node, Edge } from 'reactflow';
import { AuthorizedMemberOption } from '../../../../../utils/authorizedMembers';
import type { FilterGroup } from '../../../../../utils/filters/filtersHelpers-types';

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

export enum CommentMode {
  disabled = 'disabled',
  allowed = 'allowed',
  required = 'required',
}
export type CommentModeType = `${CommentMode}`;

export type Transition = {
  event: string;
  asyncActions?: Action[];
  syncActions?: Action[];
  conditions?: { filters: FilterGroup };
  comment?: CommentModeType;
};

export const FEATURE_NAME = 'Workflow';

export const NEW_EVENT_NAME = 'NEW_EVENT';

export const NEW_STATUS_NAME = 'NEW_STATUS';

export enum WorkflowNodeType {
  status = 'status',
  transition = 'transition',
  placeholder = 'placeholder',
}

export enum WorkflowDataType {
  // Actions
  syncActions = 'syncActions',
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

// Label weight for nodes lit by a hover. A text shadow, not font-weight: a bolder label could
// widen a status chip, and React Flow would then re-measure the node and re-run the layout.
export const HIGHLIGHT_LABEL_SHADOW = '0 0 0.6px currentColor';

const formatActions = (actions: Action[] = []) => {
  return actions.map(({ type, params }) => {
    if (type === 'updateAuthorizedMembers') {
      return {
        type,
        params: { authorized_members: (params as { authorized_members: AuthorizedMemberOption[] }).authorized_members
          .map(({ value, accessRight, groupsRestriction }) => ({
            id: value,
            access_right: accessRight,
            groups_restriction_ids: groupsRestriction?.map((g) => g.value) ?? [],
          })) },
      };
    }
    if (type === 'validateDraft') {
      return {
        type,
      };
    }
    if (type === 'shareWithOrganizations') {
      const orgIds = ((params as { organizations?: (string | { value: string })[] })?.organizations ?? []).map((o) => (typeof o === 'string' ? o : o.value));
      return {
        type: 'asyncBulkAction',
        params: {
          scope: 'KNOWLEDGE',
          actions: [{ type: 'SHARE', context: { values: orgIds } }],
          failOnAnyError: true,
        },
      };
    }
    if (type === 'unshareFromOrganizations') {
      const orgIds = ((params as { organizations?: (string | { value: string })[] })?.organizations ?? []).map((o) => (typeof o === 'string' ? o : o.value));
      return {
        type: 'asyncBulkAction',
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

// When the graph holds no status node (empty draft / reset), do NOT fall back to the
// server's initialState: that would carry a stale value into an otherwise empty schema.
// Use the wildcard '*' instead — the backend treats it as a neutral initial state and
// skips state-existence checks for it. This also keeps this function's output aligned
// between handleReset and the autosave effect, preventing a spurious follow-up mutation.
// The backend requires the initial state to be the only status without an incoming edge
// (ROOT_STATE_MISMATCH), so that status is the initial one. The saved initial state is kept only
// where the backend does not decide: no root (every status is reached by a loop), or several roots
// (MULTIPLE_ROOT_STATES) when it is one of them. Otherwise the first root takes over.
const getInitialState = (nodes: Node[], edges: Edge[], savedInitialState: string | null | undefined) => {
  const statusNodes = nodes.filter((node) => node.type === WorkflowNodeType.status);
  if (statusNodes.length === 0) return '*';
  const roots: string[] = statusNodes.filter(({ id }) => !edges.some((e) => e.target === id)).map((n) => n.data.statusTemplate.id);
  if (roots.length === 1) return roots[0];
  const candidates = roots.length ? roots : statusNodes.map((n) => n.data.statusTemplate?.id);
  if (savedInitialState && candidates.includes(savedInitialState)) return savedInitialState;
  return roots[0] || savedInitialState;
};

const transformToWorkflowDefinition = (
  nodes: Node[],
  edges: Edge[],
  workflowDefinition: { readonly id?: string; readonly name?: string; readonly initialState?: string | null } | null | undefined,
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
      const { event, conditions = {}, comment, asyncActions = [], syncActions = [] } = node.data;
      // Find ALL incoming edges (From Status -> This Transition)
      const incomingEdges = edges.filter((e) => e.target === node.id);
      // Find ALL outgoing edges (This Transition -> To Status)
      const outgoingEdges = edges.filter((e) => e.source === node.id);

      // Collect all source state IDs
      const fromStates = incomingEdges
        .map((inEdge) => nodes.find((n) => n.id === inEdge.source)?.data.statusTemplate.id)
        .filter(Boolean) as string[];

      const actionPayload = {
        event,
        conditions: conditions ?? {},
        asyncActions: formatActions(asyncActions),
        syncActions: formatActions(syncActions),
        comment,
      };

      // Fan out: one SerializedTransition per (from, to) pair.
      // SerializedTransition.from is always a single string — never an array —
      // so the backend's getTransitions(currentState) strict-equality check works correctly.
      const toStates = outgoingEdges.length > 0
        ? outgoingEdges.map((outEdge) => nodes.find((n) => n.id === outEdge.target)?.data.statusTemplate.id || null)
        : [null as string | null];

      return fromStates.flatMap((from) =>
        toStates.map((to) => ({ ...actionPayload, from, to })),
      );
    }
    return [];
  });

  // 3. Identify Initial State
  const initialState = getInitialState(nodes, edges, workflowDefinition?.initialState);

  return {
    id: workflowDefinition?.id,
    name: workflowDefinition?.name,
    initialState,
    states,
    transitions,
  };
};

const isElementStatus = (selectedElement: Node) => (selectedElement?.type === WorkflowNodeType.status || selectedElement?.type === WorkflowNodeType.placeholder);
const isNewElementStatus = (selectedElement: Node) => (selectedElement?.type === WorkflowNodeType.placeholder);

export {
  getInitialState,
  transformToWorkflowDefinition,
  isElementStatus,
  isNewElementStatus,
};
