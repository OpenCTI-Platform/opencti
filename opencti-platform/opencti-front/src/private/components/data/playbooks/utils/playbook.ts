import { Edge } from 'reactflow';
import { PlaybookComponent } from '../types/playbook-types';

interface LinkDefinition {
  id: string,
  from: {
    port: string,
    id: string
  },
  to: {
    id: string
  }
}

interface ComputedNodesReturns {
  id: string;
  type: string;
  position: { x: number, y: number };
  data: {
    name: string;
    configuration: string; // json
    component?: PlaybookComponent | null;
    openConfig: (nodeId: string) => void;
    openReplace: (nodeId: string) => void;
    openAddSibling: (nodeId: string) => void;
    openDelete: (nodeId: string) => void;
  };
}

interface ComputeNodeDefinition {
  id: string,
  name: string,
  position: { x: number, y: number },
  component_id: string,
  configuration: string // json
}

export const computeNodes = (
  playbookNodes: ComputeNodeDefinition[],
  playbookComponents: readonly (PlaybookComponent | null | undefined)[],
  setAction: React.Dispatch<React.SetStateAction<string | null>>,
  setSelectedNode: React.Dispatch<React.SetStateAction<string | null>>,
): ComputedNodesReturns[] => {
  return playbookNodes.map((node) => {
    const component = playbookComponents
      .filter((playbookComponent) => playbookComponent?.id === node?.component_id)
      .at(0);
    return {
      id: node.id,
      type: 'workflow',
      position: node.position,
      data: {
        name: node.name,
        configuration: node.configuration ? JSON.parse(node.configuration) : null,
        component,
        openConfig: (nodeId) => {
          setSelectedNode(nodeId);
          setAction('config');
        },
        openReplace: (nodeId) => {
          setSelectedNode(nodeId);
          setAction('replace');
        },
        openAddSibling: (nodeId) => {
          setSelectedNode(nodeId);
          setAction('add');
        },
        openDelete: (nodeId) => {
          setSelectedNode(nodeId);
          setAction('delete');
        },
      },
    };
  });
};

export const computeEdges = (
  playbookEdges: LinkDefinition[], 
  setAction: React.Dispatch<React.SetStateAction<string | null>>, 
  setSelectedEdge: React.Dispatch<React.SetStateAction<string | null>>
): Edge[] => {
  return playbookEdges.map((edge) => {
    return {
      id: edge.id,
      type: 'workflow',
      source: edge.from.id,
      sourceHandle: edge.from.port,
      target: edge.to.id,
      data: {
        openConfig: (edgeId: string) => {
          setSelectedEdge(edgeId);
          setAction('config');
        },
      },
    };
  });
};

export const addPlaceholders = (
  nodes: ComputedNodesReturns[], 
  edges: Edge[], 
  setAction:React.Dispatch<React.SetStateAction<string | null>>, 
  setSelectedNode:React.Dispatch<React.SetStateAction<string | null>>
) => {
  if (nodes.length === 0) {
    return {
      nodes: [
        {
          id: 'PLACEHOLDER-ORIGIN',
          type: 'placeholder',
          position: { x: 0, y: 0 },
          data: {
            name: '+',
            configuration: null,
            component: { is_entry_point: true },
            openConfig: (nodeId: string) => {
              setSelectedNode(nodeId);
              setAction('config');
            },
          },
        },
      ],
      edges: [],
    };
  }
  // Search for nodes with outputs and without connected nodes
  const nodesOutputs = nodes
    .filter((node) => node.data.component?.ports)
    .map((node) => node.data.component!.ports
      .filter((port) => port.type === 'out')
      .map((port) => ({ ...node, port_id: port.id })))
    .flat();
  const notConnectedNodesOutputs = nodesOutputs.filter(
    (nodeOutput) => edges.filter((edge) => edge.source === nodeOutput.id && edge.sourceHandle === nodeOutput.port_id)
      .length === 0,
  );
  const placeholders = notConnectedNodesOutputs.map((notConnectedNodeOutput) => {
    const childPlaceholderId = `${notConnectedNodeOutput?.id}-${notConnectedNodeOutput?.port_id}-PLACEHOLDER`;
    const childPlaceholderNode = {
      id: childPlaceholderId,
      position: { x: notConnectedNodeOutput?.position.x, y: notConnectedNodeOutput?.position.y },
      type: 'placeholder',
      data: {
        name: '+',
        configuration: null,
        component: { is_entry_point: false },
        openConfig: (nodeId: string) => {
          setSelectedNode(nodeId);
          setAction('config');
        },
      },
    };
    const childPlaceholderEdge = {
      id: `${notConnectedNodeOutput?.id}-${notConnectedNodeOutput?.port_id}-${childPlaceholderId}`,
      type: 'placeholder',
      source: notConnectedNodeOutput?.id,
      sourceHandle: notConnectedNodeOutput?.port_id,
      target: childPlaceholderId,
    };
    return { node: childPlaceholderNode, edge: childPlaceholderEdge };
  });
  const placeholderNodes = placeholders.map((placeholder) => placeholder.node);
  const placeholderEdges = placeholders.map((placeholder) => placeholder.edge);
  return {
    nodes: [...nodes, ...placeholderNodes],
    edges: [...edges, ...placeholderEdges],
  };
};
