import { StatusTemplateFieldSearchQuery$data } from '@components/common/form/__generated__/StatusTemplateFieldSearchQuery.graphql';
import { useMemo } from 'react';
import { Node, Edge, MarkerType } from 'reactflow';
import { SubTypeWorkflowQuery$data } from '../../__generated__/SubTypeWorkflowQuery.graphql';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../components/Theme';
import { authorizedMembersToOptions } from '../../../../../../utils/authorizedMembers';
import { Connection, getNodes } from '../../../../../../utils/connection';

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
) => {
  const theme = useTheme<Theme>();

  return useMemo(() => {
    if (!workflowDefinition) return { initialNodes: [], initialEdges: [] };
    console.log({ workflowDefinition });

    // 1. Refactor Status Templates
    const statusTemplates: StatusTemplate = convertEdgesToObject(statusTemplatesEdges);

    // 2. Refactor Members
    const members = convertEdgesToObject(membersEdges);

    console.log({ members });
    const parseActions = (actions) => {
      // console.log('parse', { members });

      return actions.map((action) => {
        if (action.type === 'updateAuthorizedMembers') {
          return {
            ...action,
            params: { authorized_members: authorizedMembersToOptions(action?.params?.authorized_members.map((am) => ({ ...am, ...members[am.id] }))) },
          };
        }
        return action;
      });
    };

    // 1. Map states to nodes
    const stateNodes: Node[] = workflowDefinition.states.map(({ statusId, onEnter, onExit }) => ({
      id: statusId,
      type: 'status',
      data: {
        onEnter: parseActions(onEnter),
        onExit: parseActions(onExit),
        // onEnter: onEnter,
        // onExit: onExit,
        statusTemplate: statusTemplates[statusId] },
      position: { x: 0, y: 0 },
    }));

    // 2. Map transitions to transition nodes
    const transitionNodes: Node[] = workflowDefinition.transitions.map((transition) => ({
      id: `transition-${transition.from}-${transition.to}`,
      type: 'transition',
      data: {
        conditions: transition.conditions,
        // actions: transition.actions,
        actions: parseActions(transition.actions),
        event: transition.event,
      },
      position: { x: 0, y: 0 },
    }));

    // 3. Map transitions to edges
    const transitionEdges: Edge[] = workflowDefinition.transitions.flatMap((transition) => {
      const transitionId = `transition-${transition.from}-${transition.to}`;
      return [
        {
          id: `e-${transition.from}->${transitionId}`,
          type: 'transition',
          source: transition.from,
          target: transitionId,
        },
        {
          id: `e-${transitionId}->${transition.to}`,
          type: 'transition',
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
