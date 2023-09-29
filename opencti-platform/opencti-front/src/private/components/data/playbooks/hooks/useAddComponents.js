import { useReactFlow } from 'reactflow';
import React, { useState } from 'react';
import { v4 as uuid } from 'uuid';
import { graphql } from 'react-relay';
import PlaybookAddComponents from '../PlaybookAddComponents';
import { commitMutation } from '../../../../../relay/environment';
import { isNotEmptyField } from '../../../../../utils/utils';

export const useAddComponentsAddNodeMutation = graphql`
  mutation useAddComponentsAddNodeMutation($input: PlaybookAddNodeInput!) {
    playbookAddNode(input: $input)
  }
`;

export const useAddComponentsAddLinkMutation = graphql`
  mutation useAddComponentsAddLinkMutation($input: PlaybookAddLinkInput!) {
    playbookAddLink(input: $input)
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
  const addNode = (
    result,
    placeholderNode,
    parentNode,
    add,
    component,
    configuration,
    nodes,
    edges,
  ) => {
    const childPlaceholderId = uuid();
    const childPlaceholderNode = {
      id: childPlaceholderId,
      position: {
        x: placeholderNode.position.x,
        y:
          placeholderNode.type === 'placeholder'
            ? placeholderNode.position.y
            : placeholderNode.position.y + 150,
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
      id: `${result.node}-${childPlaceholderId}`,
      type: 'placeholder',
      source: result.node,
      target: childPlaceholderId,
    };
    let newNodes = nodes;
    let newEdges = edges;
    if (placeholderNode.type === 'placeholder') {
      newNodes = nodes.map((node) => {
        if (node.id === placeholderNode.id) {
          return {
            ...node,
            id: result.node,
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
        if (edge.target === placeholderNode.id) {
          return {
            ...edge,
            id: result.edge,
            type: 'workflow',
            onClick: add,
          };
        }
        return edge;
      });
    }
    setNodes([...newNodes, childPlaceholderNode]);
    setEdges([...newEdges, childPlaceholderEdge]);
  };

  const onConfig = (component, config) => {
    const position = {
      x: selectedNode.position.x,
      y: selectedNode.position.y,
    };
    commitMutation({
      mutation: useAddComponentsAddNodeMutation,
      variables: {
        input: {
          playbook_id: playbook.id,
          name: config?.name ?? component.name,
          component_id: component.id,
          position,
          configuration: config ? JSON.stringify(config) : null,
        },
      },
      onCompleted: (nodeResult) => {
        const placeholderNode = selectedNode.type === 'placeholder' ? selectedNode : null;
        const parentNode = getNodes()
          .filter(
            (n) => n.id
              === getEdges()
                .filter((o) => o.target === selectedNode.id)
                .at(0)?.target,
          )
          ?.at(0);
        if (isNotEmptyField(parentNode)) {
          commitMutation({
            mutation: useAddComponentsAddLinkMutation,
            variables: {
              input: {
                playbook_id: playbook.id,
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
                placeholderNode,
                parentNode,
                component,
                config,
                getNodes(),
                getEdges(),
              );
              setSelectedNode(null);
            },
          });
        }
        addNode(
          {
            node: nodeResult.playbookAddNode,
          },
          placeholderNode,
          parentNode,
          component,
          config,
          getNodes(),
          getEdges(),
        );
      },
    });
  };
  const renderAddComponent = () => {
    return (
      <PlaybookAddComponents
        open={selectedNode !== null}
        handleClose={() => setSelectedNode(null)}
        selectedNode={selectedNode}
        onConfig={onConfig}
        playbookComponents={playbookComponents}
      />
    );
  };
  return { setSelectedNode, renderAddComponent, addNode };
};

export default useAddComponents;
