import { useMemo } from 'react';
import { Node, Edge, MarkerType } from 'reactflow';
import { colorPalette } from '../utils'; // Adjust path
import { SubTypeWorkflowDefinitionQuery$data } from '../../__generated__/SubTypeWorkflowDefinitionQuery.graphql';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../components/Theme';

export const useWorkflowInitialElements = (workflowDefinition: SubTypeWorkflowDefinitionQuery$data['workflowDefinition']) => {
  const theme = useTheme<Theme>();

  return useMemo(() => {
    if (!workflowDefinition) return { initialNodes: [], initialEdges: [] };

    // 1. Map states to nodes
    const stateNodes: Node[] = workflowDefinition.states.map((status, index: number) => ({
      id: status.name,
      type: 'status',
      data: { ...status, color: colorPalette[index % colorPalette.length] },
      position: { x: 0, y: 0 },
    }));

    // 2. Map transitions to transition nodes
    const transitionNodes: Node[] = workflowDefinition.transitions.map((transition) => ({
      id: `transition-${transition.from}-${transition.to}`,
      type: 'transition',
      data: { conditions: transition.conditions, event: transition.event },
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
