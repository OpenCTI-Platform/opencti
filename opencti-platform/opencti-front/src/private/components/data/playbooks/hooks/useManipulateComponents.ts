import { useReactFlow, type Edge, type Node } from 'reactflow';
import { useState } from 'react';
import { graphql } from 'react-relay';
import { commitMutation } from '../../../../../relay/environment';
import type { PlaybookHistoryControls } from './usePlaybookHistory';
import { placeholderEdgeIdOf, placeholderIdOf } from '../utils/playbook';
import type {
  PlaybookAction,
  PlaybookComponent,
  PlaybookConfig,
  PlaybookConfigHandler,
  PlaybookEdge,
  PlaybookEdgeData,
  PlaybookNode,
  PlaybookNodeData,
} from '../types/playbook-types';

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

// The "+" add buttons of the canvas: a node without component, and the dashed link that leads to it.
interface PlaceholderNodeData {
  name: string;
  configuration: null;
  component: { is_entry_point: boolean };
  openConfig: (node: PlaybookNode) => void;
}
type CanvasNode = PlaybookNode | Node<PlaceholderNodeData>;

interface CreatedStep {
  nodeId: string;
  linkId?: string;
}

type HistoryRecorder = Pick<PlaybookHistoryControls, 'record' | 'reset' | 'snapshot'>;

// A step removed with its branch: the links given, every step they lead to, and so on downwards.
export const deleteEdgesAndAllChildren = <N extends Node, E extends Edge>(definitionNodes: N[], definitionEdges: E[], edges: E[]) => {
  const edgesToDelete = edges;
  const nodesToDelete: N[] = [];
  let childrenEdges: E[] = [];
  let childrenNodes = definitionNodes.filter((n) => edges.map((o) => o.target).includes(n.id));
  if (childrenNodes.length > 0) {
    nodesToDelete.push(...childrenNodes);
    childrenEdges = definitionEdges.filter((n) => childrenNodes.map((o) => o.id).includes(n.source));
  }
  while (childrenEdges.length > 0) {
    edgesToDelete.push(...childrenEdges);
    childrenNodes = definitionNodes.filter(
      (n) => edgesToDelete.map((o) => o.target).includes(n.id)
        && !nodesToDelete.map((o) => o.id).includes(n.id),
    );
    if (childrenNodes.length > 0) {
      nodesToDelete.push(...childrenNodes);
      childrenEdges = definitionEdges.filter((n) => childrenNodes.map((o) => o.id).includes(n.source));
    } else {
      childrenEdges = [];
    }
  }
  return {
    nodes: definitionNodes.filter(
      (n) => !nodesToDelete.map((o) => o.id).includes(n.id),
    ),
    edges: definitionEdges.filter(
      (n) => !edgesToDelete.map((o) => o.id).includes(n.id),
    ),
  };
};

const outPortsOf = (component: PlaybookComponent) => component.ports.filter((n) => n.type === 'out');

// history: the undo / redo controls of usePlaybookHistory; every change made here is recorded
// there with the playbook it was made on.
const useManipulateComponents = (playbook: { id: string }, history?: HistoryRecorder) => {
  const [selectedNode, setSelectedNode] = useState<PlaybookNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<PlaybookEdge | null>(null);
  const [action, setAction] = useState<PlaybookAction | null>(null);
  const { getNode, getNodes, getEdges, setNodes, setEdges } = useReactFlow<PlaybookNodeData | PlaceholderNodeData, PlaybookEdgeData>();

  // region callbacks carried by the canvas elements
  const openNode = (nextAction: PlaybookAction) => (node: PlaybookNode) => {
    setSelectedNode(node);
    setAction(nextAction);
  };
  const openEdge = (edge: PlaybookEdge) => {
    setSelectedEdge(edge);
    setAction('config');
  };
  const stepData = (
    component: PlaybookComponent,
    name: string,
    configuration: PlaybookConfig | null,
    description?: string,
  ): PlaybookNodeData => ({
    name,
    description,
    configuration: configuration ?? undefined,
    component,
    openConfig: openNode('config'),
    openReplace: openNode('replace'),
    openAddSibling: openNode('add'),
    openDelete: openNode('delete'),
  });
  const placeholderData = (isEntryPoint = false): PlaceholderNodeData => ({
    name: '+',
    configuration: null,
    component: { is_entry_point: isEntryPoint },
    openConfig: openNode('config'),
  });
  // An add button on each given out port of a step, at the step's place (the layout moves it).
  // Its id is the one the canvas gives it when the playbook is loaded (placeholderIdOf), so a "+" keeps
  // the same id whether it was drawn by an edit or by a reload.
  const placeholdersOn = (
    sourceId: string,
    ports: PlaybookComponent['ports'],
    position: { x: number; y: number },
  ) => ({
    nodes: ports.map((n): Node<PlaceholderNodeData> => ({
      id: placeholderIdOf(sourceId, n.id),
      position: { x: position.x, y: position.y },
      type: 'placeholder',
      data: placeholderData(),
    })),
    edges: ports.map((n): Edge => ({
      id: placeholderEdgeIdOf(sourceId, n.id),
      type: 'placeholder',
      source: sourceId,
      sourceHandle: n.id,
      target: placeholderIdOf(sourceId, n.id),
      data: { openConfig: openNode('config') },
    })),
  });
  // endregion

  // region local graph
  const applyAddNodeFromPlaceholder = (
    node: PlaybookNode,
    result: CreatedStep,
    component: PlaybookComponent,
    name: string,
    configuration: PlaybookConfig | null,
    description?: string,
  ) => {
    const children = placeholdersOn(result.nodeId, outPortsOf(component), node.position);
    setNodes((nodes) => nodes
      .map((n) => (n.id === node.id
        ? { ...n, id: result.nodeId, type: 'workflow', data: stepData(component, name, configuration, description) }
        : n))
      .concat(children.nodes));
    setEdges((edges) => edges
      .map((edge) => (edge.target === node.id
        ? { ...edge, id: result.linkId ?? edge.id, type: 'workflow', target: result.nodeId, data: { openConfig: openEdge } }
        : edge))
      .concat(children.edges as PlaybookEdge[]));
  };
  const applyAddNode = (
    node: PlaybookNode,
    result: CreatedStep,
    component: PlaybookComponent,
    name: string,
    configuration: PlaybookConfig | null,
    originEdge: Edge,
    description?: string,
  ) => {
    const newNode: PlaybookNode = {
      id: result.nodeId,
      position: { x: node.position.x, y: node.position.y },
      type: 'workflow',
      data: stepData(component, name, configuration, description),
    };
    const newEdge: PlaybookEdge = {
      id: result.linkId ?? `${originEdge.source}-${originEdge.sourceHandle}-${result.nodeId}`,
      type: 'workflow',
      source: originEdge.source,
      sourceHandle: originEdge.sourceHandle,
      target: result.nodeId,
      data: { openConfig: openEdge },
    };
    const children = placeholdersOn(result.nodeId, outPortsOf(component), node.position);
    setNodes((nodes) => nodes.concat([...children.nodes, newNode]));
    setEdges((edges) => edges.concat([...(children.edges as PlaybookEdge[]), newEdge]));
  };
  const applyInsertNode = (
    edge: PlaybookEdge,
    result: CreatedStep,
    component: PlaybookComponent,
    name: string,
    configuration: PlaybookConfig | null,
    description?: string,
  ) => {
    let newNodes: CanvasNode[] = getNodes() as CanvasNode[];
    let newEdges: Edge[] = getEdges();
    const targetNode = getNode(edge.target);
    if (!targetNode) return;
    newNodes.push({
      id: result.nodeId,
      position: { x: targetNode.position.x, y: targetNode.position.y },
      type: 'workflow',
      data: stepData(component, name, configuration, description),
    });
    // Connect the parent node to the new node using the existing link
    newEdges = newEdges.map((e) => {
      if (e.source === edge.source && e.sourceHandle === edge.sourceHandle && e.target === targetNode.id) {
        return { ...e, type: 'workflow', target: result.nodeId, data: { openConfig: openEdge } };
      }
      return e;
    });
    const firstPort = component.ports.at(0);
    if (!firstPort) {
      // A step without ports ends the branch: everything below it goes.
      newNodes = newNodes.filter((n) => n.id !== targetNode.id);
      newEdges = newEdges.filter((n) => n.target !== targetNode.id);
      const edgesToDelete = newEdges.filter((n) => n.source === targetNode.id);
      const deleteResult = deleteEdgesAndAllChildren(newNodes, newEdges, edgesToDelete);
      newNodes = deleteResult.nodes;
      newEdges = deleteResult.edges;
    } else {
      // Otherwise its first port leads to the step that was below the link.
      newEdges.push({
        id: result.linkId ?? `${result.nodeId}-${firstPort.id}-${edge.target}`,
        type: 'workflow',
        source: result.nodeId,
        sourceHandle: firstPort.id,
        target: edge.target,
        data: { openConfig: openEdge },
      });
      if (component.ports.length > 1) {
        const children = placeholdersOn(result.nodeId, component.ports.slice(1), targetNode.position);
        newNodes.push(...children.nodes);
        newEdges.push(...children.edges);
      }
    }
    setNodes(newNodes);
    setEdges(newEdges as PlaybookEdge[]);
  };
  const applyReplaceNode = (
    node: PlaybookNode,
    component: PlaybookComponent,
    name: string,
    configuration: PlaybookConfig | null,
    description?: string,
  ) => {
    let newEdges: Edge[] = getEdges();
    let newNodes: CanvasNode[] = (getNodes() as CanvasNode[]).map((n) => (n.id === node.id
      ? { ...n, id: node.id, type: 'workflow', data: stepData(component, name, configuration, description) }
      : n));
    const previousPorts = node.data.component?.ports ?? [];
    if (previousPorts.length < component.ports.length) {
      // The new component has more ports: an add button on each new one.
      const end = component.ports.length - previousPorts.length + (previousPorts.length > 0 ? 1 : 0);
      const children = placeholdersOn(node.id, component.ports.slice(previousPorts.length, end), node.position);
      newNodes.push(...children.nodes);
      newEdges.push(...children.edges);
    } else if (previousPorts.length > component.ports.length) {
      // Fewer ports: what hung on the ports that are gone is deleted.
      for (let i = previousPorts.length - 1; i >= component.ports.length; i -= 1) {
        const edgesToDelete = newEdges.filter((n) => n.source === node.id && n.sourceHandle === previousPorts[i].id);
        const result = deleteEdgesAndAllChildren(newNodes, newEdges, edgesToDelete);
        newNodes = result.nodes;
        newEdges = result.edges;
      }
    }
    setNodes(newNodes);
    setEdges(newEdges as PlaybookEdge[]);
  };
  const applyDeleteNode = (node: PlaybookNode) => {
    const allEdges = getEdges();
    // start by removing the node and the edges that leads to it
    let newNodes: CanvasNode[] = (getNodes() as CanvasNode[]).filter((n) => n.id !== node.id);
    let newEdges: Edge[] = allEdges.filter((e) => e.target !== node.id);
    // then delete the edges that come out of the node, and all children underneath
    const edgesToDelete = newEdges.filter((n) => n.source === node.id);
    const result = deleteEdgesAndAllChildren(newNodes, newEdges, edgesToDelete);
    newNodes = result.nodes;
    newEdges = result.edges;
    const originEdge = allEdges.find((o) => o.target === node.id);
    const parentNode = getNodes().find((n) => n.id === originEdge?.source);
    const otherEdgesToParentNode = allEdges.filter(
      (o) => o.source === originEdge?.source && o.sourceHandle === originEdge?.sourceHandle,
    );
    const freedPortId = originEdge?.sourceHandle ?? 'out';
    if (originEdge && otherEdgesToParentNode.length === 1) {
      // inserting placeholder in place of the node
      newNodes.push({
        id: placeholderIdOf(originEdge.source, freedPortId),
        position: { x: node.position.x, y: node.position.y },
        type: 'placeholder',
        data: placeholderData(),
      });
    } else if (otherEdgesToParentNode.length <= 1) {
      // inserting placeholder of origin (entry point)
      newNodes.push({
        id: 'PLACEHOLDER-ORIGIN',
        type: 'placeholder',
        position: { x: 0, y: 0 },
        data: placeholderData(true),
      });
    }
    if (parentNode && originEdge && otherEdgesToParentNode.length === 1) {
      // If the parent node is not the topmost node,
      // we need a placeholder edge that leads to the placeholder node
      newEdges.push({
        id: placeholderEdgeIdOf(parentNode.id, freedPortId),
        type: 'placeholder',
        source: parentNode.id,
        sourceHandle: originEdge.sourceHandle,
        target: placeholderIdOf(parentNode.id, freedPortId),
        data: { openConfig: openNode('config') },
      });
    }
    setNodes(newNodes);
    setEdges(newEdges as PlaybookEdge[]);
  };
  // endregion

  const closeSelection = () => {
    setSelectedNode(null);
    setSelectedEdge(null);
    setAction(null);
  };
  const stepSpec = (component: PlaybookComponent, name: string, position: { x: number; y: number }, jsonConfig: string | null, description?: string) => ({
    name,
    component_id: component.id,
    position,
    configuration: jsonConfig,
    ...(description ? { description } : {}),
  });

  // region backend graph
  const addNodeFromPlaceholder = (node: PlaybookNode, component: PlaybookComponent, name: string, config: PlaybookConfig | null, description?: string) => {
    const jsonConfig = config ? JSON.stringify(config) : null;
    const position = { x: node.position.x, y: node.position.y };
    const placeholderEdge = getEdges().find((o) => o.target === node.id);
    const parentNode = getNodes().find((n) => n.id === placeholderEdge?.source);
    const parent = parentNode && placeholderEdge?.sourceHandle
      ? { parentNodeId: parentNode.id, parentPortId: placeholderEdge.sourceHandle }
      : null;
    const before = history?.snapshot();
    // The node and the link to its parent are created by one mutation: the
    // backend refuses a node without parent unless it is the entry point.
    commitMutation({
      mutation: useManipulateComponentsAddNodeMutation,
      variables: {
        id: playbook.id,
        input: { name, component_id: component.id, position, configuration: jsonConfig, description, ...(parent ?? {}) },
      },
      onCompleted: (nodeResult: { playbookAddNode: string }) => {
        const nodeId = nodeResult.playbookAddNode;
        if (before) {
          history?.record({
            kind: 'add',
            nodeId,
            node: stepSpec(component, name, position, jsonConfig, description),
            ...(parent ?? {}),
          }, before, { nodeId });
        }
        applyAddNodeFromPlaceholder(
          node,
          { nodeId, linkId: parent ? `${parent.parentNodeId}-${parent.parentPortId}-${nodeId}` : undefined },
          component,
          name,
          config,
          description,
        );
        closeSelection();
      },
    });
  };
  const addNode = (node: PlaybookNode, component: PlaybookComponent, name: string, config: PlaybookConfig | null, description?: string) => {
    const jsonConfig = config ? JSON.stringify(config) : null;
    const position = { x: node.position.x, y: node.position.y };
    const originEdge = getEdges().find((o) => o.target === node.id);
    const parentNode = getNodes().find((n) => n.id === originEdge?.source);
    // A sibling shares the parent of the selected node; the entry point has
    // none, so no sibling can be added to it.
    if (!originEdge || !parentNode || !originEdge.sourceHandle) {
      closeSelection();
      return;
    }
    const parentPortId = originEdge.sourceHandle;
    const before = history?.snapshot();
    commitMutation({
      mutation: useManipulateComponentsAddNodeMutation,
      variables: {
        id: playbook.id,
        input: {
          name,
          component_id: component.id,
          position,
          configuration: jsonConfig,
          description,
          parentNodeId: parentNode.id,
          parentPortId,
        },
      },
      onCompleted: (nodeResult: { playbookAddNode: string }) => {
        const nodeId = nodeResult.playbookAddNode;
        if (before) {
          history?.record({
            kind: 'add',
            nodeId,
            node: stepSpec(component, name, position, jsonConfig, description),
            parentNodeId: parentNode.id,
            parentPortId,
          }, before, { nodeId });
        }
        applyAddNode(
          node,
          { nodeId, linkId: `${parentNode.id}-${parentPortId}-${nodeId}` },
          component,
          name,
          config,
          originEdge,
          description,
        );
        closeSelection();
      },
    });
  };
  const insertNode = (edge: PlaybookEdge, component: PlaybookComponent, name: string, config: PlaybookConfig | null, description?: string) => {
    const jsonConfig = config ? JSON.stringify(config) : null;
    const targetNode = getNode(edge.target);
    if (!targetNode || !edge.sourceHandle) {
      closeSelection();
      return;
    }
    const position = { x: targetNode.position.x, y: targetNode.position.y };
    commitMutation({
      mutation: useManipulateComponentsInsertNodeMutation,
      variables: {
        id: playbook.id,
        parentNodeId: edge.source,
        parentPortId: edge.sourceHandle,
        childNodeId: edge.target,
        input: { name, component_id: component.id, position, configuration: jsonConfig, description },
      },
      onCompleted: (insertResult: { playbookInsertNode: CreatedStep }) => {
        // An insertion on a link has no single inverse operation: the history ends here.
        history?.reset();
        applyInsertNode(edge, insertResult.playbookInsertNode, component, name, config, description);
        closeSelection();
      },
    });
  };
  const replaceNode = (node: PlaybookNode, component: PlaybookComponent, name: string, config: PlaybookConfig | null, description?: string) => {
    const position = { x: node.position.x, y: node.position.y };
    const jsonConfig = config ? JSON.stringify(config) : null;
    const before = history?.snapshot();
    commitMutation({
      mutation: useManipulateComponentsReplaceNodeMutation,
      variables: {
        id: playbook.id,
        nodeId: node.id,
        input: { name, component_id: component.id, position, configuration: jsonConfig, description },
      },
      onCompleted: () => {
        if (before) {
          history?.record({
            kind: 'replace',
            nodeId: node.id,
            node: stepSpec(component, name, position, jsonConfig, description),
          }, before);
        }
        applyReplaceNode(node, component, name, config, description);
        closeSelection();
      },
    });
  };
  const deleteNode = () => {
    const node = selectedNode;
    if (!node) return;
    const before = history?.snapshot();
    commitMutation({
      mutation: useManipulateComponentsDeleteNodeMutation,
      variables: { id: playbook.id, nodeId: node.id },
      onCompleted: () => {
        // A step deleted with its branch has no inverse: recording it ends the history.
        if (before) history?.record({ kind: 'delete', nodeId: node.id }, before);
        applyDeleteNode(node);
        closeSelection();
      },
    });
  };
  // endregion

  const onConfigAdd: PlaybookConfigHandler = (component, name, config, description) => {
    if (!component) return;
    if (selectedNode && action === 'config') {
      // We are in a placeholder
      addNodeFromPlaceholder(selectedNode, component, name, config, description);
    } else if (selectedNode && action === 'add') {
      addNode(selectedNode, component, name, config, description);
    } else if (selectedEdge) {
      // We are in an edge
      insertNode(selectedEdge, component, name, config, description);
    }
  };
  const onConfigReplace: PlaybookConfigHandler = (component, name, config, description) => {
    if (!component || !selectedNode) return;
    replaceNode(selectedNode, component, name, config, description);
  };

  return {
    action,
    setAction,
    selectedNode,
    setSelectedNode,
    selectedEdge,
    setSelectedEdge,
    onConfigAdd,
    onConfigReplace,
    deleteNode,
  };
};

export default useManipulateComponents;
