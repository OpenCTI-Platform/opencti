export const computeNodes = (playbookNodes, playbookComponents) => {
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
        configuration: n.configuration,
        component,
      },
    };
  });
};

export const computeEdges = (playbookEdges) => {
  return playbookEdges.map((n) => {
    return {
      id: n.id,
      type: 'workflow',
      source: n.from.id,
      sourceHandle: n.from.port,
      target: n.to.id,
    };
  });
};

export const addPlaceholders = (nodes, edges, add) => {
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
            component: null,
            isEntryPoint: true,
            onClick: add,
          },
        },
      ],
      edges: [],
    };
  }
  // Search for nodes with outputs and without connected nodes
  const notConnectedNodes = nodes.filter(
    (n) => n.data.component.ports.filter((o) => o.type === 'out').length > 0
      && edges.filter((o) => o.source === n.id).length === 0,
  );
  const placeholders = notConnectedNodes.map((n) => {
    const childPlaceholderId = `${n.id}-PLACEHOLDER`;
    const childPlaceholderNode = {
      id: childPlaceholderId,
      position: { x: n.position.x, y: n.position.y },
      type: 'placeholder',
      data: {
        name: '+',
        configuration: null,
        component: null,
        onClick: add,
      },
    };
    const childPlaceholderEdge = {
      id: `${n.id}-${childPlaceholderId}`,
      type: 'placeholder',
      source: n.id,
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
