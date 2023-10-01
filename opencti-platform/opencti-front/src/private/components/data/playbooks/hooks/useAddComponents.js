import { useReactFlow } from 'reactflow';
import React, { useState } from 'react';
import { v4 as uuid } from 'uuid';
import { graphql } from 'react-relay';
import PlaybookAddComponents from '../PlaybookAddComponents';
import { commitMutation } from '../../../../../relay/environment';

export const useAddComponentsAddNodeMutation = graphql`
  mutation useAddComponentsAddNodeMutation(
    $id: ID!
    $input: PlaybookAddNodeInput!
  ) {
    playbookAddNode(id: $id, input: $input)
  }
`;

export const useAddComponentsAddLinkMutation = graphql`
  mutation useAddComponentsAddLinkMutation(
    $id: ID!
    $input: PlaybookAddLinkInput!
  ) {
    playbookAddLink(id: $id, input: $input)
  }
`;

export const useAddComponentsReplaceNodeMutation = graphql`
  mutation useAddComponentsReplaceNodeMutation(
    $id: ID!
    $nodeId: ID!
    $input: PlaybookAddNodeInput!
  ) {
    playbookReplaceNode(id: $id, nodeId: $nodeId, input: $input)
  }
`;

export const useAddComponentsInsertNodeMutation = graphql`
  mutation useAddComponentsInsertNodeMutation(
    $id: ID!
    $parentNodeId: ID!
    $parentPortId: ID!
    $childNodeId: ID!
    $input: PlaybookAddNodeInput!
  ) {
    playbookInsertNode(
      id: $id
      parentNodeId: $parentNodeId
      parentPortId: $parentPortId
      childNodeId: $childNodeId
      input: $input
    ) {
      nodeId
      linkId
    }
  }
`;

export const useAddComponentsDeleteNodeMutation = graphql`
  mutation useAddComponentsDeleteNodeMutation($id: ID!, $nodeId: ID!) {
    playbookDeleteNode(id: $id, nodeId: $nodeId) {
      id
    }
  }
`;

export const useAddComponentsDeleteLinkMutation = graphql`
  mutation useAddComponentsDeleteLinkMutation($id: ID!, $linkId: ID!) {
    playbookDeleteLink(id: $id, linkId: $linkId) {
      id
    }
  }
`;

const computeOrphanLinks = (selectedNode, component, edges) => edges
  .filter(
    (n) => n.source === selectedNode.id
        && !component.ports.map((o) => o.id).includes(n.sourceHandle),
  )
  .map((n) => n.id);

const useAddComponents = (playbook, playbookComponents) => {
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const { getNode, getNodes, getEdges, setNodes, setEdges } = useReactFlow();
  // region local graph
  const applyAddNodeFromPlaceholder = (result, component, configuration) => {
    const childPlaceholderId = uuid();
    const childPlaceholderNodes = component.ports
      .filter((n) => n.type === 'out')
      .map((n) => ({
        id: `${childPlaceholderId}-${n.id}`,
        position: {
          x: selectedNode.position.x,
          y: selectedNode.position.y,
        },
        type: 'placeholder',
        data: {
          name: '+',
          configuration: null,
          component: { is_entry_point: false },
          onClick: setSelectedNode,
        },
      }));
    const childPlaceholderEdges = component.ports
      .filter((n) => n.type === 'out')
      .map((n) => ({
        id: `${result.nodeId}-${childPlaceholderId}-${n.id}`,
        type: 'placeholder',
        source: result.nodeId,
        sourceHandle: n.id,
        target: `${childPlaceholderId}-${n.id}`,
        data: {
          onClick: setSelectedNode,
        },
      }));
    setNodes((nodes) => nodes
      .map((node) => {
        if (node.id === selectedNode.id) {
          return {
            ...node,
            id: result.nodeId,
            type: 'workflow',
            data: {
              name: configuration?.name ?? component.name,
              configuration,
              component,
              onClick: setSelectedNode,
            },
          };
        }
        return node;
      })
      .concat(childPlaceholderNodes));
    setEdges((edges) => edges
      .map((edge) => {
        if (edge.target === selectedNode.id) {
          return {
            ...edge,
            id: result.linkId,
            type: 'workflow',
            target: result.nodeId,
            data: {
              onClick: setSelectedEdge,
            },
          };
        }
        return edge;
      })
      .concat(childPlaceholderEdges));
  };
  const applyInsertNode = (result, component, configuration) => {
    const targetNode = getNode(selectedEdge.target);
    const newNode = {
      id: result.nodeId,
      position: { x: targetNode.position.x, y: targetNode.position.y },
      type: 'workflow',
      data: {
        name: configuration?.name ?? component.name,
        configuration,
        component,
        onClick: setSelectedNode,
      },
    };
    const newEdge = {
      id: result.linkId,
      type: 'workflow',
      source: result.nodeId,
      sourceHandle: component.ports.at(0).id,
      target: selectedEdge.target,
      data: {
        onClick: setSelectedEdge,
      },
    };
    let newNodes = [newNode];
    let newEdges = [newEdge];
    if (component.ports.length > 1) {
      const childPlaceholderId = uuid();
      newNodes = [
        newNode,
        ...component.ports.slice(1).map((n) => ({
          id: `${childPlaceholderId}-${n.id}`,
          position: {
            x: targetNode.position.x,
            y: targetNode.position.y,
          },
          type: 'placeholder',
          data: {
            name: '+',
            configuration: null,
            component: { is_entry_point: false },
            onClick: setSelectedNode,
          },
        })),
      ];
      newEdges = [
        newEdge,
        ...component.ports.slice(1).map((n) => ({
          id: `${result.nodeId}-${childPlaceholderId}-${n.id}`,
          type: 'placeholder',
          source: result.nodeId,
          sourceHandle: n.id,
          target: `${childPlaceholderId}-${n.id}`,
          data: {
            onClick: setSelectedNode,
          },
        })),
      ];
    }
    setNodes((nodes) => nodes.concat(newNodes));
    setEdges((edges) => edges
      .map((edge) => {
        if (edge.source === selectedEdge.source) {
          return {
            ...edge,
            type: 'workflow',
            target: result.nodeId,
            data: {
              onClick: setSelectedEdge,
            },
          };
        }
        return edge;
      })
      .concat(newEdges));
  };
  const applyReplaceNode = (component, configuration) => {
    let newNodes = getNodes().map((node) => {
      if (node.id === selectedNode.id) {
        return {
          ...node,
          id: selectedNode.id,
          type: 'workflow',
          data: {
            name: configuration?.name ?? component.name,
            configuration,
            component,
            onClick: setSelectedNode,
          },
        };
      }
      return node;
    });
    // Links connected to inexisting ports
    let newEdges = getEdges();
    let linksToDelete = computeOrphanLinks(selectedNode, component, newEdges);
    while (linksToDelete.length > 0) {
      // eslint-disable-next-line @typescript-eslint/no-loop-func
      newEdges = newEdges.filter((n) => !linksToDelete.includes(n.id));
      newNodes = newNodes.filter(
        // eslint-disable-next-line @typescript-eslint/no-loop-func
        (n) => newEdges.filter((o) => o.source === n.id || o.target === n.id)
          .length > 0,
      );
      linksToDelete = computeOrphanLinks(selectedNode, component, newEdges);
    }

    setNodes(newNodes);
    setEdges(newEdges);
  };
  // endregion
  // region backend graph
  const addNodeFromPlaceholder = (component, config) => {
    const jsonConfig = config ? JSON.stringify(config) : null;
    const position = {
      x: selectedNode.position.x,
      y: selectedNode.position.y,
    };
    commitMutation({
      mutation: useAddComponentsAddNodeMutation,
      variables: {
        id: playbook.id,
        input: {
          name: config?.name ?? component.name,
          component_id: component.id,
          position,
          configuration: jsonConfig,
        },
      },
      onCompleted: (nodeResult) => {
        const placeholderEdge = getEdges()
          .filter((o) => o.target === selectedNode.id)
          ?.at(0);
        const parentNode = getNodes()
          .filter((n) => n.id === placeholderEdge?.source)
          ?.at(0);
        // This is an entry point
        if (!parentNode) {
          applyAddNodeFromPlaceholder(
            { nodeId: nodeResult.playbookAddNode },
            component,
            config,
          );
        } else {
          commitMutation({
            mutation: useAddComponentsAddLinkMutation,
            variables: {
              id: playbook.id,
              input: {
                from_node: parentNode.id,
                from_port: placeholderEdge.sourceHandle,
                to_node: nodeResult.playbookAddNode,
              },
            },
            onCompleted: (linkResult) => {
              applyAddNodeFromPlaceholder(
                {
                  nodeId: nodeResult.playbookAddNode,
                  linkId: linkResult.playbookAddLink,
                },
                component,
                config,
              );
            },
          });
        }
        setSelectedNode(null);
      },
    });
  };
  const insertNode = (component, config) => {
    const jsonConfig = config ? JSON.stringify(config) : null;
    const targetNode = getNode(selectedEdge.target);
    const position = {
      x: targetNode.position.x,
      y: targetNode.position.y,
    };
    commitMutation({
      mutation: useAddComponentsInsertNodeMutation,
      variables: {
        id: playbook.id,
        parentNodeId: selectedEdge.source,
        parentPortId: selectedEdge.sourceHandle,
        childNodeId: selectedEdge.target,
        input: {
          name: config?.name ?? component.name,
          component_id: component.id,
          position,
          configuration: jsonConfig,
        },
      },
      onCompleted: (insertResult) => {
        applyInsertNode(
          {
            nodeId: insertResult.playbookInsertNode.nodeId,
            linkId: insertResult.playbookInsertNode.linkId,
          },
          component,
          config,
        );
        setSelectedEdge(null);
      },
    });
  };
  const replaceNode = (component, config) => {
    const position = {
      x: selectedNode.position.x,
      y: selectedNode.position.y,
    };
    const jsonConfig = config ? JSON.stringify(config) : null;
    commitMutation({
      mutation: useAddComponentsReplaceNodeMutation,
      variables: {
        id: playbook.id,
        nodeId: selectedNode.id,
        input: {
          name: config?.name ?? component.name,
          component_id: component.id,
          position,
          configuration: jsonConfig,
        },
      },
      onCompleted: () => {
        applyReplaceNode(component, config);
        setSelectedNode(null);
      },
    });
  };
  // endregion
  const onConfigAdd = (component, config) => {
    // We are in a placeholder
    if (selectedNode) {
      addNodeFromPlaceholder(component, config);
    } else if (selectedEdge) {
      // We are in an edge
      insertNode(component, config);
    }
  };
  const onConfigReplace = (component, config) => {
    replaceNode(component, config);
  };
  const renderAddComponent = () => {
    return (
      <PlaybookAddComponents
        open={selectedNode !== null || selectedEdge !== null}
        setSelectedNode={setSelectedNode}
        setSelectedEdge={setSelectedEdge}
        selectedNode={selectedNode}
        selectedEdge={selectedEdge}
        onConfigAdd={onConfigAdd}
        onConfigReplace={onConfigReplace}
        playbookComponents={playbookComponents}
      />
    );
  };
  return { setSelectedNode, setSelectedEdge, renderAddComponent };
};

export default useAddComponents;
