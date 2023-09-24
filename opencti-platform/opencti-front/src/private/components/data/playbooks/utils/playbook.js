import { v4 as uuid } from 'uuid';

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
          id: uuid(),
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
    const childPlaceholderId = uuid();
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

export const addNode = (
  originNode,
  component,
  configuration,
  nodes,
  edges,
  add,
) => {
  const childPlaceholderId = uuid();
  const childPlaceholderNode = {
    id: childPlaceholderId,
    position: {
      x: originNode.position.x,
      y: originNode.type === 'placeholder' ? originNode.position.y : originNode.position.y + 150,
    },
    type: 'placeholder',
    data: {
      name: '+',
      configuration: null,
      component: null,
      onClick: add,
    },
  };
  const childPlaceholderEdge = {
    id: `${originNode.id}-${childPlaceholderId}`,
    type: 'placeholder',
    source: originNode.id,
    target: childPlaceholderId,
  };
  let newNodes = nodes;
  let newEdges = edges;
  if (originNode.type === 'placeholder') {
    newNodes = nodes.map((node) => {
      if (node.id === originNode.id) {
        return {
          ...node,
          type: 'workflow',
          data: {
            name: component.name,
            configuration,
            component,
            onClick: add,
          },
        };
      }
      return node;
    });
    newEdges = edges.map((edge) => {
      if (edge.target === originNode.id) {
        return {
          ...edge,
          type: 'workflow',
          onClick: add,
        };
      }
      return edge;
    });
  }
  return {
    nodes: [...newNodes, childPlaceholderNode],
    edges: [...newEdges, childPlaceholderEdge],
  };
};
