import { useReactFlow } from 'reactflow';
import React, { useState } from 'react';
import { v4 as uuid } from 'uuid';
import { graphql } from 'react-relay';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { commitMutation } from '../../../../../relay/environment';
import PlaybookAddComponents from '../PlaybookAddComponents';
import Transition from '../../../../../components/Transition';
import { useFormatter } from '../../../../../components/i18n';

export const useManipulateComponentsPlaybookUpdatePositionsMutation = graphql`
  mutation useManipulateComponentsPlaybookUpdatePositionsMutation(
    $id: ID!
    $positions: String!
  ) {
    playbookUpdatePositions(id: $id, positions: $positions)
  }
`;

export const useManipulateComponentsAddNodeMutation = graphql`
  mutation useManipulateComponentsAddNodeMutation(
    $id: ID!
    $input: PlaybookAddNodeInput!
  ) {
    playbookAddNode(id: $id, input: $input)
  }
`;

export const useManipulateComponentsAddLinkMutation = graphql`
  mutation useManipulateComponentsAddLinkMutation(
    $id: ID!
    $input: PlaybookAddLinkInput!
  ) {
    playbookAddLink(id: $id, input: $input)
  }
`;

export const useManipulateComponentsReplaceNodeMutation = graphql`
  mutation useManipulateComponentsReplaceNodeMutation(
    $id: ID!
    $nodeId: ID!
    $input: PlaybookAddNodeInput!
  ) {
    playbookReplaceNode(id: $id, nodeId: $nodeId, input: $input)
  }
`;

export const useManipulateComponentsInsertNodeMutation = graphql`
  mutation useManipulateComponentsInsertNodeMutation(
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

export const useManipulateComponentsDeleteNodeMutation = graphql`
  mutation useManipulateComponentsDeleteNodeMutation($id: ID!, $nodeId: ID!) {
    playbookDeleteNode(id: $id, nodeId: $nodeId) {
      id
    }
  }
`;

export const useManipulateComponentsDeleteLinkMutation = graphql`
  mutation useManipulateComponentsDeleteLinkMutation($id: ID!, $linkId: ID!) {
    playbookDeleteLink(id: $id, linkId: $linkId) {
      id
    }
  }
`;

const deleteEdgesAndAllChildren = (definitionNodes, definitionEdges, edges) => {
  const edgesToDelete = edges;
  const nodesToDelete = [];
  let childrenEdges = [];
  let childrenNodes = definitionNodes.filter((n) => edges.map((o) => o.target).includes(n.id));
  if (childrenNodes.length > 0) {
    nodesToDelete.push(...childrenNodes);
    childrenEdges = definitionEdges.filter((n) => childrenNodes.map((o) => o.id).includes(n.source));
  }
  while (childrenEdges.length > 0) {
    edgesToDelete.push(...childrenEdges);
    childrenNodes = definitionNodes.filter((n) => edgesToDelete.map((o) => o.target).includes(n.id) && !nodesToDelete.map((o) => o.id).includes(n.id));
    if (childrenNodes.length > 0) {
      nodesToDelete.push(...childrenNodes);
      // eslint-disable-next-line @typescript-eslint/no-loop-func
      childrenEdges = definitionEdges.filter((n) => childrenNodes.map((o) => o.id).includes(n.source));
    } else {
      childrenEdges = [];
    }
  }
  return {
    nodes: definitionNodes.filter((n) => !nodesToDelete.map((o) => o.id).includes(n.id)),
    edges: definitionEdges.filter((n) => !edgesToDelete.map((o) => o.id).includes(n.id)),
  };
};

const useManipulateComponents = (playbook, playbookComponents) => {
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const [action, setAction] = useState(null);
  const { getNode, getNodes, getEdges, setNodes, setEdges } = useReactFlow();
  // region local graph
  const applyAddNodeFromPlaceholder = (
    result,
    component,
    name,
    configuration,
  ) => {
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
          openConfig: (nodeId) => {
            setSelectedNode(nodeId);
            setAction('config');
          },
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
          openConfig: (nodeId) => {
            setSelectedNode(nodeId);
            setAction('config');
          },
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
              name,
              configuration,
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
              openConfig: (edgeId) => {
                setSelectedEdge(edgeId);
                setAction('config');
              },
            },
          };
        }
        return edge;
      })
      .concat(childPlaceholderEdges));
  };
  const applyAddNode = (result, component, name, configuration, originEdge) => {
    const newNode = {
      id: result.nodeId,
      position: { x: selectedNode.position.x, y: selectedNode.position.y },
      type: 'workflow',
      data: {
        name,
        configuration,
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
    const newEdge = {
      id: result.linkId,
      type: 'workflow',
      source: originEdge.source,
      sourceHandle: originEdge.sourceHandle,
      target: result.nodeId,
      data: {
        openConfig: (edgeId) => {
          setSelectedEdge(edgeId);
          setAction('config');
        },
      },
    };
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
          openConfig: (nodeId) => {
            setSelectedNode(nodeId);
            setAction('config');
          },
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
          openConfig: (nodeId) => {
            setSelectedNode(nodeId);
            setAction('config');
          },
        },
      }));
    setNodes((nodes) => nodes.concat([...childPlaceholderNodes, newNode]));
    setEdges((edges) => edges.concat([...childPlaceholderEdges, newEdge]));
  };
  const applyInsertNode = (result, component, name, configuration) => {
    const targetNode = getNode(selectedEdge.target);
    const newNode = {
      id: result.nodeId,
      position: { x: targetNode.position.x, y: targetNode.position.y },
      type: 'workflow',
      data: {
        name,
        configuration,
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
    const newEdge = {
      id: result.linkId,
      type: 'workflow',
      source: result.nodeId,
      sourceHandle: component.ports.at(0).id,
      target: selectedEdge.target,
      data: {
        openConfig: (edgeId) => {
          setSelectedEdge(edgeId);
          setAction('config');
        },
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
            openConfig: (nodeId) => {
              setSelectedNode(nodeId);
              setAction('config');
            },
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
            openConfig: (nodeId) => {
              setSelectedNode(nodeId);
              setAction('config');
            },
          },
        })),
      ];
    }
    setNodes((nodes) => nodes.concat(newNodes));
    setEdges((edges) => edges
      .map((edge) => {
        if (
          edge.source === selectedEdge.source
            && edge.sourceHandle === selectedEdge.sourceHandle
        ) {
          return {
            ...edge,
            type: 'workflow',
            target: result.nodeId,
            data: {
              openConfig: (edgeId) => {
                setSelectedEdge(edgeId);
                setAction('config');
              },
            },
          };
        }
        return edge;
      })
      .concat(newEdges));
  };
  const applyReplaceNode = (component, name, configuration) => {
    let newEdges = getEdges();
    let newNodes = getNodes().map((node) => {
      if (node.id === selectedNode.id) {
        return {
          ...node,
          id: selectedNode.id,
          type: 'workflow',
          data: {
            name,
            configuration,
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
      }
      return node;
    });
    if (selectedNode.data.component.ports.length < component.ports.length) {
      const childPlaceholderId = uuid();
      for (
        let i = 1;
        i <= component.ports.length - selectedNode.data.component.ports.length;
        // eslint-disable-next-line no-plusplus
        i++
      ) {
        const port = component.ports[i];
        newNodes.push({
          id: `${childPlaceholderId}-${port.id}`,
          position: {
            x: selectedNode.position.x,
            y: selectedNode.position.y,
          },
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
        });
        newEdges.push({
          id: `${selectedNode.nodeId}-${childPlaceholderId}-${port.id}`,
          type: 'placeholder',
          source: selectedNode.id,
          sourceHandle: port.id,
          target: `${childPlaceholderId}-${port.id}`,
          data: {
            openConfig: (nodeId) => {
              setSelectedNode(nodeId);
              setAction('config');
            },
          },
        });
      }
    } else if (selectedNode.data.component.ports.length > component.ports.length) {
      // eslint-disable-next-line no-plusplus
      for (let i = 1; i <= selectedNode.data.component.ports.length - component.ports.length; i++) {
        // Find all links to the port
        const edgesToDelete = newEdges.filter((n) => n.source === selectedNode.id && n.sourceHandle === selectedNode.data.component.ports[i].id);
        const result = deleteEdgesAndAllChildren(newNodes, newEdges, edgesToDelete);
        newNodes = result.nodes;
        newEdges = result.edges;
      }
    }
    setNodes(newNodes);
    setEdges(newEdges);
  };
  const applyDeleteNode = () => {
    let newNodes = getNodes().filter((n) => n.id !== selectedNode.id);
    let newEdges = getEdges();
    const edgesToDelete = newEdges.filter((n) => n.source === selectedNode.id);
    const result = deleteEdgesAndAllChildren(newNodes, newEdges, edgesToDelete);
    newNodes = result.nodes;
    newEdges = result.edges;
    const originEdge = getEdges()
      .filter((o) => o.target === selectedNode.id)
      ?.at(0);
    const parentNode = getNodes()
      .filter((n) => n.id === originEdge?.source)
      ?.at(0);
    const childPlaceholderId = uuid();
    newNodes.push({
      id: `${childPlaceholderId}-${originEdge.sourceHandle}`,
      position: {
        x: parentNode.position.x,
        y: parentNode.position.y,
      },
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
    });
    newEdges.push({
      id: `${selectedNode.nodeId}-${childPlaceholderId}-${originEdge.sourceHandle}`,
      type: 'placeholder',
      source: originEdge.source,
      sourceHandle: originEdge.sourceHandle,
      target: `${childPlaceholderId}-${originEdge.sourceHandle}`,
      data: {
        openConfig: (nodeId) => {
          setSelectedNode(nodeId);
          setAction('config');
        },
      },
    });
    setNodes(newNodes);
    setEdges(newEdges);
  };
  // endregion
  // region backend graph
  const addNodeFromPlaceholder = (component, name, config) => {
    const jsonConfig = config ? JSON.stringify(config) : null;
    const position = {
      x: selectedNode.position.x,
      y: selectedNode.position.y,
    };
    commitMutation({
      mutation: useManipulateComponentsAddNodeMutation,
      variables: {
        id: playbook.id,
        input: {
          name,
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
            name,
            config,
          );
        } else {
          commitMutation({
            mutation: useManipulateComponentsAddLinkMutation,
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
                name,
                config,
              );
            },
          });
        }
        setSelectedNode(null);
        setAction(null);
      },
    });
  };
  const addNode = (component, name, config) => {
    const jsonConfig = config ? JSON.stringify(config) : null;
    const position = {
      x: selectedNode.position.x,
      y: selectedNode.position.y,
    };
    commitMutation({
      mutation: useManipulateComponentsAddNodeMutation,
      variables: {
        id: playbook.id,
        input: {
          name,
          component_id: component.id,
          position,
          configuration: jsonConfig,
        },
      },
      onCompleted: (nodeResult) => {
        const originEdge = getEdges()
          .filter((o) => o.target === selectedNode.id)
          ?.at(0);
        const parentNode = getNodes()
          .filter((n) => n.id === originEdge?.source)
          ?.at(0);
        commitMutation({
          mutation: useManipulateComponentsAddLinkMutation,
          variables: {
            id: playbook.id,
            input: {
              from_node: parentNode.id,
              from_port: originEdge.sourceHandle,
              to_node: nodeResult.playbookAddNode,
            },
          },
          onCompleted: (linkResult) => {
            applyAddNode(
              {
                nodeId: nodeResult.playbookAddNode,
                linkId: linkResult.playbookAddLink,
              },
              component,
              name,
              config,
              originEdge,
            );
          },
        });
        setSelectedNode(null);
        setAction(null);
      },
    });
  };
  const insertNode = (component, name, config) => {
    const jsonConfig = config ? JSON.stringify(config) : null;
    const targetNode = getNode(selectedEdge.target);
    const position = {
      x: targetNode.position.x,
      y: targetNode.position.y,
    };
    commitMutation({
      mutation: useManipulateComponentsInsertNodeMutation,
      variables: {
        id: playbook.id,
        parentNodeId: selectedEdge.source,
        parentPortId: selectedEdge.sourceHandle,
        childNodeId: selectedEdge.target,
        input: {
          name,
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
          name,
          config,
        );
        setSelectedEdge(null);
        setAction(null);
      },
    });
  };
  const replaceNode = (component, name, config) => {
    const position = {
      x: selectedNode.position.x,
      y: selectedNode.position.y,
    };
    const jsonConfig = config ? JSON.stringify(config) : null;
    commitMutation({
      mutation: useManipulateComponentsReplaceNodeMutation,
      variables: {
        id: playbook.id,
        nodeId: selectedNode.id,
        input: {
          name,
          component_id: component.id,
          position,
          configuration: jsonConfig,
        },
      },
      onCompleted: () => {
        applyReplaceNode(component, name, config);
        setSelectedNode(null);
        setAction(null);
      },
    });
  };
  const deleteNode = () => {
    commitMutation({
      mutation: useManipulateComponentsDeleteNodeMutation,
      variables: {
        id: playbook.id,
        nodeId: selectedNode.id,
      },
      onCompleted: () => {
        applyDeleteNode();
        setSelectedNode(null);
        setAction(null);
      },
    });
  };
  // endregion
  const onConfigAdd = (component, name, config) => {
    // We are in a placeholder
    if (selectedNode && action === 'config') {
      addNodeFromPlaceholder(component, name, config);
    } else if (selectedNode && action === 'add') {
      addNode(component, name, config);
    } else if (selectedEdge) {
      // We are in an edge
      insertNode(component, name, config);
    }
  };
  const onConfigReplace = (component, name, config) => {
    replaceNode(component, name, config);
  };
  const renderManipulateComponents = () => {
    const { t } = useFormatter();
    return (
      <>
        <PlaybookAddComponents
          action={action}
          setSelectedNode={setSelectedNode}
          setSelectedEdge={setSelectedEdge}
          selectedNode={selectedNode}
          selectedEdge={selectedEdge}
          onConfigAdd={onConfigAdd}
          onConfigReplace={onConfigReplace}
          playbookComponents={playbookComponents}
        />
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={selectedNode !== null && action === 'delete'}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={() => {
            setSelectedNode(null);
            setAction(null);
          }}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this node?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={() => {
                setSelectedNode(null);
                setAction(null);
              }}
            >
              {t('Cancel')}
            </Button>
            <Button color="secondary" onClick={deleteNode}>
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
      </>
    );
  };
  return {
    setAction,
    setSelectedNode,
    setSelectedEdge,
    renderManipulateComponents,
  };
};

export default useManipulateComponents;
