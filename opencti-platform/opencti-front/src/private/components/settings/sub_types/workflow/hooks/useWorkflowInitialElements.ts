import { StatusTemplateFieldSearchQuery$data } from '@components/common/form/__generated__/StatusTemplateFieldSearchQuery.graphql';
import { useMemo } from 'react';
import { Node, Edge, MarkerType } from 'reactflow';
import { SubTypeWorkflowDefinitionQuery$data } from '../../__generated__/SubTypeWorkflowDefinitionQuery.graphql';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../components/Theme';
import { authorizedMembersToOptions } from '../../../../../../utils/authorizedMembers';

type StatusTemplate = { [key: string]: { color: string; id: string; name: string } };

// const fintelTemplateExportQuery = graphql`
//   query useFintelTemplateExportQuery($id: ID!) {
//     fintelTemplate(id: $id) {
//       name
//       toConfigurationExport
//     }
//   }
// `;
export const useWorkflowInitialElements = (
  workflowDefinition: SubTypeWorkflowDefinitionQuery$data['workflowDefinition'],
  statusTemplatesEdges: StatusTemplateFieldSearchQuery$data['statusTemplates'],
) => {
  const theme = useTheme<Theme>();

  return useMemo(() => {
    // const members = await fetchQuery(objectMembersFieldSearchQuery, {
    //   search: '',
    //   first: 100,
    // })
    //   .toPromise()
    //   .then((data) => {
    //     return (
    //       (data as ObjectMembersFieldSearchQuery$data)?.members?.edges ?? []
    //     ).reduce((acc, n) => {
    //       acc[n?.node.id] = n?.node;
    //       return acc;
    //     }, {});
    //   });

    // const parseActions = (actions) => {
    //   // console.log('parse', { members });

    //   return actions.map((action) => {
    //     if (action.type === 'updateAuthorizedMembers') {
    //       return {
    //         ...action,
    //         params: { authorized_members: authorizedMembersToOptions(action?.params?.authorized_members.map((am) => ({ ...am, ...members[am.id] }))) },
    //       };
    //     }
    //     return action;
    //   });
    // };
    // // console.log({ members });

    if (!workflowDefinition || !statusTemplatesEdges?.edges?.length) return { initialNodes: [], initialEdges: [] };
    console.log({ workflowDefinition });

    const statusTemplates: StatusTemplate = (statusTemplatesEdges?.edges ?? []).reduce(
      (acc, edge) => {
        const node = edge?.node;
        if (node?.id) {
          acc[node.id] = {
            id: node.id,
            name: node.name,
            color: node.color,
          };
        }
        return acc;
      },
      {} as StatusTemplate,
    );

    // 1. Map states to nodes
    const stateNodes: Node[] = workflowDefinition.states.map(({ name, onEnter, onExit }) => ({
      id: name,
      type: 'status',
      data: {
        // onEnter: parseActions(onEnter),
        onEnter: onEnter,
        onExit: onExit,
        // onExit: parseActions(onExit),
        statusTemplate: statusTemplates[name] },
      position: { x: 0, y: 0 },
    }));

    // 2. Map transitions to transition nodes
    const transitionNodes: Node[] = workflowDefinition.transitions.map((transition) => ({
      id: `transition-${transition.from}-${transition.to}`,
      type: 'transition',
      data: {
        conditions: transition.conditions,
        actions: transition.actions,
        // actions: parseActions(transition.actions),
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
