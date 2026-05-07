import { useTheme } from '@mui/styles';
import { useMemo } from 'react';
import { Edge, MarkerType, Node } from 'reactflow';
import type { Theme } from '../../../../../../components/Theme';
import { AuthorizedMembers, authorizedMembersToOptions } from '../../../../../../utils/authorizedMembers';
import { Connection, getNodes } from '../../../../../../utils/connection';
import { SubTypeWorkflowQuery$data } from '../../__generated__/SubTypeWorkflowQuery.graphql';
import { Action, CommentMode, CommentModeType, WorkflowNodeType } from '../utils';

type ReadOnlyAction = NonNullable<NonNullable<SubTypeWorkflowQuery$data['workflowDefinition']>['states'][0]['onEnter']>[0]
  | NonNullable<NonNullable<SubTypeWorkflowQuery$data['workflowDefinition']>['states'][0]['onExit']>[0]
  | NonNullable<NonNullable<SubTypeWorkflowQuery$data['workflowDefinition']>['transitions'][0]['actions']>[0];

type StatusTemplate = { [key: string]: { color: string; id: string; name: string } };

const convertEdgesToObject = <T extends { id: string }>(
  connection: Connection<T | null | undefined>,
): Record<string, T> => {
  if (!connection) return {};
  return Object.fromEntries(
    getNodes(connection).map((node) => [node.id, node as T]),
  );
};

export const useWorkflowInitialElements = (
  workflowDefinition: SubTypeWorkflowQuery$data['workflowDefinition'],
  statusTemplatesEdges: SubTypeWorkflowQuery$data['statusTemplates'],
  membersEdges: SubTypeWorkflowQuery$data['members'],
  organizationsEdges: SubTypeWorkflowQuery$data['organizations'] | null,
) => {
  const theme = useTheme<Theme>();

  return useMemo(() => {
    if (!workflowDefinition) return { initialNodes: [], initialEdges: [] };

    const statusTemplates: StatusTemplate = convertEdgesToObject(statusTemplatesEdges);
    const members = convertEdgesToObject(membersEdges);
    const organizations = convertEdgesToObject(organizationsEdges);

    // Populate authorized members
    const parseActions = (actions?: ReadonlyArray<ReadOnlyAction> | null): Action[] => {
      if (!actions) {
        return [];
      }

      return actions.map((action) => {
        if (action.type === 'updateAuthorizedMembers') {
          return {
            ...action,
            params: {
              authorized_members: authorizedMembersToOptions(
                (action?.params as { authorized_members: AuthorizedMembers })
                  ?.authorized_members
                  ?.map((am) => ({
                    ...am,
                    ...members[am.id],
                  })) ?? null,
              ),
            },
          };
        }
        if (action.type === 'asyncBulkAction') {
          // Reverse-map backend asyncBulkAction → frontend shareWithOrganizations / unshareFromOrganizations
          const innerType = (action?.params as { actions?: { type?: string; context?: { values?: string[] } }[] })?.actions?.[0]?.type;
          const orgIds: string[] = (action?.params as { actions?: { type?: string; context?: { values?: string[] } }[] })?.actions?.[0]?.context?.values ?? [];
          const frontendType = innerType === 'UNSHARE' ? 'unshareFromOrganizations' : 'shareWithOrganizations';
          return {
            type: frontendType,
            mode: action.mode,
            params: { organizations: orgIds.map((id) => ({ value: id, label: organizations[id]?.name ?? id })) },
          } as Action;
        }
        return { ...action } as Action;
      });
    };

    // 1. Map states to nodes
    const stateNodes: Node[] = workflowDefinition.states
      .map(({ statusId, onEnter = [], onExit = [] }) => ({
        id: statusId,
        type: WorkflowNodeType.status,
        data: {
          onEnter: parseActions(onEnter),
          onExit: parseActions(onExit),
          statusTemplate: statusTemplates[statusId] },
        position: { x: 0, y: 0 },
      }));

    // 2. Map transitions to transition nodes
    const transitionNodes: Node[] = workflowDefinition.transitions
      .map(({ from, to, event, conditions = {}, actions = [], comment, asyncActions = [], syncActions = [] }) => ({
        id: `${WorkflowNodeType.transition}-${from}-${to}`,
        type: WorkflowNodeType.transition,
        data: {
          event,
          conditions,
          actions: parseActions(actions),
          comment: (comment ?? CommentMode.disabled) as CommentModeType,
          asyncActions: parseActions((asyncActions ?? []) as ReadonlyArray<ReadOnlyAction>),
          syncActions: parseActions((syncActions ?? []) as ReadonlyArray<ReadOnlyAction>),
        },
        position: { x: 0, y: 0 },
      }));

    // 3. Map transitions to edges
    const transitionEdges: Edge[] = workflowDefinition.transitions.flatMap((transition) => {
      const transitionId = `${WorkflowNodeType.transition}-${transition.from}-${transition.to}`;
      return [
        {
          id: `e-${transition.from}->${transitionId}`,
          type: WorkflowNodeType.transition,
          source: transition.from,
          target: transitionId,
        },
        {
          id: `e-${transitionId}->${transition.to}`,
          type: WorkflowNodeType.transition,
          source: transitionId,
          target: transition.to,
          markerEnd: { type: MarkerType.ArrowClosed, color: theme.palette.chip?.main },
        },
      ];
    });

    return {
      initialNodes: [...stateNodes, ...transitionNodes],
      initialEdges: [...transitionEdges],
    };
  }, [workflowDefinition]);
};
