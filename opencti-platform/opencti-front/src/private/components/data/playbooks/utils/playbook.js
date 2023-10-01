export const computeNodes = (
  playbookNodes,
  playbookComponents,
  setAction,
  setSelectedNode,
) => {
  return playbookNodes.map((n) => {
    const component = playbookComponents
      .filter((o) => o.id === n.component_id)
      .at(0);
    return {
      id: n.id,
      type: 'workflow',
      position: n.position,
      data: {
        name: n.name,
        configuration: n.configuration ? JSON.parse(n.configuration) : null,
        component,
        openConfig: (nodeId) => {
          setSelectedNode(nodeId);
          setAction('config');
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

export const computeEdges = (playbookEdges, setAction, setSelectedEdge) => {
  return playbookEdges.map((n) => {
    return {
      id: n.id,
      type: 'workflow',
      source: n.from.id,
      sourceHandle: n.from.port,
      target: n.to.id,
      data: {
        openConfig: (edgeId) => {
          setSelectedEdge(edgeId);
          setAction('config');
        },
      },
    };
  });
};

export const addPlaceholders = (nodes, edges, setAction, setSelectedNode) => {
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
            openConfig: (nodeId) => {
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
    .map((n) => n.data.component.ports
      .filter((o) => o.type === 'out')
      .map((o) => ({ ...n, port_id: o.id })))
    .flat();
  const notConnectedNodesOutputs = nodesOutputs.filter(
    (n) => edges.filter((o) => o.source === n.id && o.sourceHandle === n.port_id)
      .length === 0,
  );
  const placeholders = notConnectedNodesOutputs.map((n) => {
    const childPlaceholderId = `${n.id}-${n.port_id}-PLACEHOLDER`;
    const childPlaceholderNode = {
      id: childPlaceholderId,
      position: { x: n.position.x, y: n.position.y },
      type: 'placeholder',
      data: {
        name: '+',
        configuration: null,
        component: { is_entry_point: false },
        openConfig: (nodeId) => {
          setSelectedNode(nodeId);
          setAction('config');
        },
      },
    };
    const childPlaceholderEdge = {
      id: `${n.id}-${n.port_id}-${childPlaceholderId}`,
      type: 'placeholder',
      source: n.id,
      sourceHandle: n.port_id,
      target: childPlaceholderId,
    };
    return { node: childPlaceholderNode, edge: childPlaceholderEdge };
  });
  const placeholderNodes = placeholders.map((n) => n.node);
  const placeholderEdges = placeholders.map((n) => n.edge);
  return {
    nodes: [...nodes, ...placeholderNodes],
    edges: [...edges, ...placeholderEdges],
  };
};
