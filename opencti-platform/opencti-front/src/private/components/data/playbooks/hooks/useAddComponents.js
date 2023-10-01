import { useReactFlow } from 'reactflow';
import React, { useState } from 'react';
import { v4 as uuid } from 'uuid';
import { graphql } from 'react-relay';
import PlaybookAddComponents from '../PlaybookAddComponents';
import { commitMutation } from '../../../../../relay/environment';
import { isNotEmptyField } from '../../../../../utils/utils';

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

const useAddComponents = (playbook, playbookComponents) => {
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const { getNode, getNodes, getEdges, setNodes, setEdges } = useReactFlow();
  const addNode = (result, component, configuration) => {
    const childPlaceholderId = uuid();
    const childPlaceholderNode = {
      id: childPlaceholderId,
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
    };
    const childPlaceholderEdge = {
      id: `${result.node}-${childPlaceholderId}`,
      type: 'placeholder',
      source: result.node,
      target: childPlaceholderId,
      data: {
        onClick: setSelectedNode,
      },
    };
    setNodes((nodes) => nodes
      .map((node) => {
        if (node.id === selectedNode.id) {
          return {
            ...node,
            id: result.node,
            type: 'workflow',
            data: {
              name: component.name,
              configuration,
              component,
              onClick: setSelectedNode,
            },
          };
        }
        return node;
      })
      .concat([childPlaceholderNode]));
    setEdges((edges) => edges
      .map((edge) => {
        if (edge.target === selectedNode.id) {
          return {
            ...edge,
            id: result.edge,
            type: 'workflow',
            target: result.node,
            data: {
              onClick: setSelectedEdge,
            },
          };
        }
        return edge;
      })
      .concat([childPlaceholderEdge]));
  };
  const insertNode = (result, component, configuration) => {
    const targetNode = getNode(selectedEdge.target);
    const newNode = {
      id: result.node,
      position: { x: targetNode.position.x, y: targetNode.position.y },
      type: 'workflow',
      data: {
        name: component.name,
        configuration,
        component,
        onClick: setSelectedNode,
      },
    };
    const newEdge = {
      id: result.edge,
      type: 'workflow',
      source: result.node,
      target: selectedEdge.target,
      data: {
        onClick: setSelectedEdge,
      },
    };
    setNodes((nodes) => nodes.concat([newNode]));
    setEdges((edges) => edges
      .map((edge) => {
        if (edge.source === selectedEdge.source) {
          return {
            ...edge,
            type: 'workflow',
            target: result.node,
            data: {
              onClick: setSelectedEdge,
            },
          };
        }
        return edge;
      })
      .concat([newEdge]));
  };
  const configNode = (component, configuration) => {
    setNodes((nodes) => nodes.map((node) => {
      if (node.id === selectedNode.id) {
        return {
          ...node,
          id: selectedNode.id,
          type: 'workflow',
          data: {
            name: component.name,
            configuration,
            component,
            onClick: setSelectedNode,
          },
        };
      }
      return node;
    }));
  };
  const onConfigAdd = (component, config) => {
    const configuration = config ? JSON.stringify(config) : null;
    const targetNode = selectedNode || getNode(selectedEdge.target);
    const position = {
      x: targetNode.position.x,
      y: targetNode.position.y,
    };
    // We are in a placeholder
    if (selectedNode) {
      commitMutation({
        mutation: useAddComponentsAddNodeMutation,
        variables: {
          id: playbook.id,
          input: {
            name: config?.name ?? component.name,
            component_id: component.id,
            position,
            configuration,
          },
        },
        onCompleted: (nodeResult) => {
          const parentNode = getNodes()
            .filter(
              (n) => n.id
                === getEdges()
                  .filter((o) => o.target === selectedNode.id)
                  .at(0)?.source,
            )
            ?.at(0);
          if (isNotEmptyField(parentNode)) {
            return commitMutation({
              mutation: useAddComponentsAddLinkMutation,
              variables: {
                id: playbook.id,
                input: {
                  from_node: parentNode.id,
                  from_port: parentNode.data.port ?? 'out',
                  to_node: nodeResult.playbookAddNode,
                },
              },
              onCompleted: (linkResult) => {
                addNode(
                  {
                    node: nodeResult.playbookAddNode,
                    edge: linkResult.playbookAddLink,
                  },
                  component,
                  configuration,
                );
                setSelectedNode(null);
              },
            });
          }
          addNode(
            {
              node: nodeResult.playbookAddNode,
            },
            component,
            configuration,
          );
          return setSelectedNode(null);
        },
      });
    }
    // We are in an edge
    // The parent node is now linked to the new node
    return commitMutation({
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
          configuration,
        },
      },
      onCompleted: (insertResult) => {
        insertNode(
          {
            node: insertResult.playbookInsertNode.nodeId,
            edge: insertResult.playbookInsertNode.linkId,
          },
          component,
          configuration,
        );
        setSelectedEdge(null);
      },
    });
  };
  const onConfigReplace = (component, config) => {
    const position = {
      x: selectedNode.position.x,
      y: selectedNode.position.y,
    };
    const configuration = config ? JSON.stringify(config) : null;
    commitMutation({
      mutation: useAddComponentsReplaceNodeMutation,
      variables: {
        id: playbook.id,
        nodeId: selectedNode.id,
        input: {
          name: config?.name ?? component.name,
          component_id: component.id,
          position,
          configuration,
        },
      },
      onCompleted: () => {
        configNode(component, configuration);
        return setSelectedNode(null);
      },
    });
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
  return { setSelectedNode, setSelectedEdge, renderAddComponent, addNode };
};

export default useAddComponents;
