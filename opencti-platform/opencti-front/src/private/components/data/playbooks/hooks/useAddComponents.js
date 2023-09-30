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
  const { getNodes, getEdges, setNodes, setEdges } = useReactFlow();
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
      },
    };
    const childPlaceholderEdge = {
      id: `${result.node}-${childPlaceholderId}`,
      type: 'placeholder',
      source: result.node,
      target: childPlaceholderId,
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
          };
        }
        return edge;
      })
      .concat([childPlaceholderEdge]));
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
          },
        };
      }
      return node;
    }));
  };
  const onConfigAdd = (component, config) => {
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
          configuration: config ? JSON.stringify(config) : null,
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
                config,
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
          config,
        );
        return setSelectedNode(null);
      },
    });
  };
  const onConfigReplace = (component, config) => {
    const position = {
      x: selectedNode.position.x,
      y: selectedNode.position.y,
    };
    commitMutation({
      mutation: useAddComponentsReplaceNodeMutation,
      variables: {
        id: playbook.id,
        nodeId: selectedNode.id,
        input: {
          name: config?.name ?? component.name,
          component_id: component.id,
          position,
          configuration: config ? JSON.stringify(config) : null,
        },
      },
      onCompleted: () => {
        configNode(component, config);
        return setSelectedNode(null);
      },
    });
  };
  const renderAddComponent = () => {
    return (
      <PlaybookAddComponents
        open={selectedNode !== null}
        setSelectedNode={setSelectedNode}
        selectedNode={selectedNode}
        onConfigAdd={onConfigAdd}
        onConfigReplace={onConfigReplace}
        playbookComponents={playbookComponents}
      />
    );
  };
  return { setSelectedNode, renderAddComponent, addNode };
};

export default useAddComponents;
