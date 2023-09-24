import { v4 as uuid } from 'uuid';
import { NodeProps, useReactFlow } from 'reactflow';

export function usePlaceholderClick(id: NodeProps['id']) {
  const { getNode, setNodes, setEdges } = useReactFlow();
  const onClick = () => {
    const parentNode = getNode(id);
    if (!parentNode) {
      return;
    }
    const childPlaceholderId = uuid();

    // create a placeholder node that will be added as a child of the clicked node
    const childPlaceholderNode = {
      id: childPlaceholderId,
      // the placeholder is placed at the position of the clicked node
      // the layout function will animate it to its new position
      position: { x: parentNode.position.x, y: parentNode.position.y },
      type: 'placeholder',
      data: { label: '+' },
    };

    // we need a connection from the clicked node to the new placeholder
    const childPlaceholderEdge = {
      id: `${parentNode.id}=>${childPlaceholderId}`,
      source: parentNode.id,
      target: childPlaceholderId,
      type: 'placeholder',
    };

    setNodes((nodes) =>
      nodes
        .map((node) => {
          // here we are changing the type of the clicked node from placeholder to workflow
          if (node.id === id) {
            return {
              ...node,
              type: 'workflow',
              data: { label: randomLabel() },
            };
          }
          return node;
        })
        // add the new placeholder node
        .concat([childPlaceholderNode])
    );

    setEdges((edges) =>
      edges
        .map((edge) => {
          // here we are changing the type of the connecting edge from placeholder to workflow
          if (edge.target === id) {
            return {
              ...edge,
              type: 'workflow',
            };
          }
          return edge;
        })
        // add the new placeholder edge
        .concat([childPlaceholderEdge])
    );
  };

  return onClick;
}

export default usePlaceholderClick;
