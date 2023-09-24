export const computeNodes = (playbookNodes, playbookComponents) => {
  return playbookNodes.map((n) => {
    const component = playbookComponents
      .filter((o) => o.id === n.component_id)
      .at(0);
    return {
      id: n.id,
      position: n.position,
      type: 'workflow',
      data: {
        isEntryPoint: component.is_entry_point,
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
      source: n.from.id,
      sourceHandle: n.from.port,
      target: n.to.id,
      type: 'workflow',
    };
  });
};

export const addPlaceholders = (nodes, edges) => {
  if (nodes.length === 0) {
    return {
      nodes: [
        {
          id: 'PLACEHOLDER',
          data: {
            isEntryPoint: true,
            name: '+',
            configuration: null,
            component: null,
          },
          position: { x: 0, y: 0 },
          type: 'placeholder',
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
  console.log(notConnectedNodes);
};
