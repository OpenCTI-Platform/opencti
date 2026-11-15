import type {
  PlaybookComponents,
  PlaybookDefinitionEdge,
  PlaybookDefinitionNode,
  PlaybookEdge,
  PlaybookNode,
  SetPlaybookAction,
  SetSelectedPlaybookEdge,
  SetSelectedPlaybookNode,
} from '../types/playbook-types';

// The "+" add button on a free out port of a step, and the dashed link leading to it: one per port,
// so its id is derived from the step and the port, whether the canvas drew it on load or after an edit.
export const placeholderIdOf = (nodeId: string, portId: string) => `${nodeId}-${portId}-PLACEHOLDER`;
export const placeholderEdgeIdOf = (nodeId: string, portId: string) => `${nodeId}-${portId}-${placeholderIdOf(nodeId, portId)}`;

// The out ports a step's stored links leave from, 'out' first then by name. A step whose component
// is not in the catalog (an AI agent component without XTM One, a removed connector) has no port
// list: its card draws these instead, so its links stay attached to it.
export const linkedOutPorts = (nodeId: string, links: PlaybookDefinitionEdge[]): string[] => {
  const ports = new Set(links.filter((link) => link.from?.id === nodeId && link.from.port).map((link) => link.from.port));
  return [...ports].sort((a, b) => (a === 'out' ? -1 : b === 'out' ? 1 : a < b ? -1 : a > b ? 1 : 0));
};

export const computeNodes = (
  playbookNodes: PlaybookDefinitionNode[],
  playbookComponents: PlaybookComponents,
  setAction: SetPlaybookAction,
  setSelectedNode: SetSelectedPlaybookNode,
  playbookLinks: PlaybookDefinitionEdge[] = [],
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
        description: node.description,
        configuration: node.configuration ? JSON.parse(node.configuration) : undefined,
        component,
        linkedPorts: component ? undefined : linkedOutPorts(node.id, playbookLinks),
        openConfig: (node: PlaybookNode) => {
          setSelectedNode(node);
          setAction('config');
        },
        openReplace: (node: PlaybookNode) => {
          setSelectedNode(node);
          setAction('replace');
        },
        openAddSibling: (node: PlaybookNode) => {
          setSelectedNode(node);
          setAction('add');
        },
        openDelete: (node: PlaybookNode) => {
          setSelectedNode(node);
          setAction('delete');
        },
      },
    };
  });
};

export const computeEdges = (
  playbookEdges: PlaybookDefinitionEdge[],
  setAction: SetPlaybookAction,
  setSelectedEdge: SetSelectedPlaybookEdge,
): PlaybookEdge[] => {
  return playbookEdges.map((edge) => {
    return {
      id: edge.id,
      type: 'workflow',
      source: edge.from.id,
      sourceHandle: edge.from.port,
      target: edge.to.id,
      data: {
        openConfig: (edge: PlaybookEdge) => {
          setSelectedEdge(edge);
          setAction('config');
        },
      },
    };
  });
};

export const addPlaceholders = (
  nodes: PlaybookNode[],
  edges: PlaybookEdge[],
  setAction: SetPlaybookAction,
  setSelectedNode: SetSelectedPlaybookNode,
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
            openConfig: (node: PlaybookNode) => {
              setSelectedNode(node);
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
    const childPlaceholderId = placeholderIdOf(notConnectedNodeOutput.id, notConnectedNodeOutput.port_id);
    const childPlaceholderNode = {
      id: childPlaceholderId,
      position: { x: notConnectedNodeOutput?.position.x, y: notConnectedNodeOutput?.position.y },
      type: 'placeholder',
      data: {
        name: '+',
        configuration: null,
        component: { is_entry_point: false },
        openConfig: (node: PlaybookNode) => {
          setSelectedNode(node);
          setAction('config');
        },
      },
    };
    const childPlaceholderEdge = {
      id: placeholderEdgeIdOf(notConnectedNodeOutput.id, notConnectedNodeOutput.port_id),
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
