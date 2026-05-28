import { Edge, Node, XYPosition } from 'reactflow';
import { PlaybookFlow_playbookComponents$data } from '../playbookFlow/__generated__/PlaybookFlow_playbookComponents.graphql';
import { PlaybookUpdateAction } from '../playbookFlow/playbookFlowFields/playbookFlowFieldsActions/playbookAction-types';

export type PlaybookComponents = NonNullable<PlaybookFlow_playbookComponents$data['playbookComponents']>;
export type PlaybookComponent = NonNullable<PlaybookComponents[number]>;

export interface PlaybookConfig {
  filters?: string;
  applyWithFilters?: string;
  actions?: PlaybookUpdateAction[];
  triggerTime?: string;
}

export interface PlaybookDefinitionNode {
  id: string;
  name: string;
  component_id: string;
  configuration: string; // json
  position: XYPosition;
  description?: string;
}

export interface PlaybookDefinitionEdge {
  id: string;
  from: {
    port: string;
    id: string;
  };
  to: {
    id: string;
  };
}

export type PlaybookNode = Node<{
  name?: string;
  description?: string;
  configuration?: PlaybookConfig;
  component?: PlaybookComponent;
  openConfig: (nodeId: string) => void;
  openReplace: (nodeId: string) => void;
  openAddSibling: (nodeId: string) => void;
  openDelete: (nodeId: string) => void;
}>;

export type PlaybookEdge = Edge<{
  openConfig: (edgeId: string) => void;
}>;

export type PlaybookComponentConfigSchema = {
  type: string;
  required: string[];
  properties: {
    [key in keyof PlaybookConfig]: {
      type: string;
      uniqueItems?: boolean;
      $ref?: string;
      // UI hint forwarded by backend components to request a specific
      // input renderer (e.g. ``textarea`` for multi-line strings).
      format?: string;
      default?: PlaybookConfig[key];
      oneOf?: unknown[];
      items?: {
        type: string;
        oneOf?: unknown[];
        properties: {
          op?: {
            type: string;
            enum: string[];
          };
        };
      };
    }
  };
};
