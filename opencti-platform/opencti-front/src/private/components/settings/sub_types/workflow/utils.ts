import type { Node, Edge } from 'reactflow';
import { SubTypeWorkflowDefinitionQuery$data } from '../__generated__/SubTypeWorkflowDefinitionQuery.graphql';

export type Condition = { field: string; operator: string; value: string }
  | { type: string };

export type Action = {
  type: string;
  params: {
    authorized_members?: string[];
  };
};

export type Status = {
  name: string;
  color?: string;
  onEnter?: Action[];
  onExit?: Action[];
};

const colorPalette = ['#4caf50', '#2196f3', '#ff9800', '#9c27b0', '#f44336', '#3f51b5', '#00bcd4', '#8bc34a', '#ff5722', '#673ab7'];

export const NODE_SIZE = { width: 160, height: 50 };

const transformToWorkflowDefinition = (nodes: Node[], edges: Edge[], workflowDefinition: SubTypeWorkflowDefinitionQuery$data['workflowDefinition']) => {
  // 1. Extract States
  const states = nodes
    .filter((node) => node.type === 'status')
    .map((node) => {
      const { color: _color, ...restData } = node.data;
      return {
        name: node.id,
        ...restData,
      };
    });

  // 2. Extract Transitions
  const transitions = nodes
    .filter((node) => node.type === 'transition')
    .map((transitionNode) => {
      const targetEdge = edges.find((e) => e.target === transitionNode.id);
      const sourceEdge = edges.find((e) => e.source === transitionNode.id);

      return {
        from: targetEdge?.source || '',
        to: sourceEdge?.target || '',
        event: transitionNode.data.event,
        conditions: transitionNode.data.conditions || [],
        actions: transitionNode.data.actions || [],
      };
    });

  // 3. Get first status
  const initialState = nodes
    .filter((node) => node.type === 'status')
    .find((transitionNode) => !edges.find((e) => e.target === transitionNode.id));

  return {
    id: workflowDefinition?.id,
    name: workflowDefinition?.name,
    initialState: initialState?.id || workflowDefinition?.initialState,
    states,
    transitions,
  };
};

export {
  colorPalette,
  transformToWorkflowDefinition,
};
