import { Dispatch, SetStateAction } from 'react';
import { PlaybookComponents, PlaybookDefinitionEdge, PlaybookDefinitionNode, PlaybookEdge, PlaybookNode } from '../types/playbook-types';

export const computeNodes = (
  playbookNodes: PlaybookDefinitionNode[],
  playbookComponents: PlaybookComponents,
  setAction: Dispatch<SetStateAction<string | null>>,
  setSelectedNode: Dispatch<SetStateAction<string | null>>,
): PlaybookNode[] => {
  return playbookNodes.map((node) => {
    const component = playbookComponents.find((playbookComponent) => {
      return playbookComponent?.id === node?.component_id;
    }) || undefined;

    return {
      id: node.id,
      type: 'workflow',
      position: node.position,
      data: {
        name: node.name,
        configuration: node.configuration ? JSON.parse(node.configuration) : undefined,
        component,
        openConfig: (nodeId: string) => {
          setSelectedNode(nodeId);
          setAction('config');
        },
        openReplace: (nodeId: string) => {
          setSelectedNode(nodeId);
          setAction('replace');
        },
        openAddSibling: (nodeId: string) => {
          setSelectedNode(nodeId);
          setAction('add');
        },
        openDelete: (nodeId: string) => {
          setSelectedNode(nodeId);
          setAction('delete');
        },
      },
    };
  });
};

export const computeEdges = (
  playbookEdges: PlaybookDefinitionEdge[],
  setAction: Dispatch<SetStateAction<string | null>>,
  setSelectedEdge: Dispatch<SetStateAction<string | null>>,
): PlaybookEdge[] => {
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
  nodes: PlaybookNode[],
  edges: PlaybookEdge[],
  setAction: Dispatch<SetStateAction<string | null>>,
  setSelectedNode: Dispatch<SetStateAction<string | null>>,
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
