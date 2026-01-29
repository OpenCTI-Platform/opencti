import React, { useCallback, useEffect, useMemo, useState } from 'react';
import ReactFlow, { addEdge, Connection, Edge, MarkerType, Node, NodeMouseHandler, Panel, useEdgesState, useNodesState, useReactFlow } from 'reactflow';
// @ts-expect-error ts-migrate(7016) FIXME: Could not find a declaration file for module 'reac... Remove this comment to see the full error message
import 'reactflow/dist/style.css';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../components/Theme';
import WorkflowEditionDrawer from './WorkflowEditionDrawer';
import useWorkflowLayout, { LayoutOptions } from './hooks/useWorkflowLayout';
import nodeTypes from './NodeTypes';
import edgeTypes from './EdgeTypes';
import { addStatus } from './hooks/useAddStatus';
import Button from '@common/button/Button';
import { SaveOutlined } from '@mui/icons-material';
import { colorPalette, transformToWorkflowDefinition } from './utils';

export function generatePath(points: number[][]) {
  const path = points.map(([x, y]) => `${x},${y}`).join(' L');
  return `M${path} Z`;
}

// TODO remove mocked value
const workflowDefinition = {
  id: 'conditions-workflow',
  name: 'Conditions Workflow',
  initialState: 'open',
  states: [{
    name: 'open',
  },
  {
    name: 'restricted',
    onEnter: [
      {
        type: 'updateAuthorizedMembers',
        params: {
          authorized_members: ['admin', 'manager'],
        },
      },
    ],
  },
  {
    name: 'validated',
  },
  {
    name: 'done',
  }],
  transitions: [
    {
      from: 'open',
      to: 'restricted',
      event: 'named_condition_event',
      conditions: [{ type: 'is-admin' }],
    },
    {
      from: 'restricted',
      to: 'validated',
      event: 'field_comparison_event',
      conditions: [{ field: 'entity.name', operator: 'eq', value: 'workspaceName' }],
    },
    {
      from: 'validated',
      to: 'done',
      event: 'mixed_conditions_event',
      conditions: [
        { type: 'is-admin' },
        { field: 'entity.name', operator: 'contains', value: 'Conditions' },
      ],
    },
  ],
};

const defaultViewport = { x: 0, y: 0, zoom: 1.5 };
const proOptions = { account: 'paid-pro', hideAttribution: true };
const fitViewOptions = {};
const defaultEdgeOptions = {
  type: 'straight',
  markerEnd: { type: MarkerType.Arrow },
  style: { strokeWidth: 2, strokeDasharray: '3 3' },
};

const Workflow = () => {
  const theme = useTheme<Theme>();
  const { fitView, getNode } = useReactFlow();

  const { initialNodes, initialEdges } = useMemo(() => {
    const statusMap = new Map();

    // 1. Map States to Nodes (1-to-1 relationship)
    const stateNodes: Node[] = workflowDefinition.states.map((status, index) => {
      statusMap.set(status.name, index);
      return {
        id: status.name,
        type: 'status',
        data: { ...status, color: colorPalette[index % colorPalette.length] },
        position: { x: 0, y: 0 },
      };
    });

    // 2. Map Transitions to Transition Nodes (1-to-1 relationship)
    const transitionNodes: Node[] = workflowDefinition.transitions.map((transition) => {
      return {
        id: `transition-${transition.from}-${transition.to}`,
        type: 'transition',
        data: { conditions: transition.conditions, event: transition.event },
        position: { x: 0, y: 0 },
      };
    });

    // 3. Map Transitions to Edges (1-to-2 relationship)
    const transitionEdges: Edge[] = workflowDefinition.transitions.flatMap((transition) => {
      const transitionId = `transition-${transition.from}-${transition.to}`;
      const edgeStyle = { stroke: theme.palette.chip?.main || '#ccc' };
      return [
        {
          id: `e-${transition.from}->${transitionId}`,
          type: 'transition',
          source: transition.from,
          target: transitionId,
        },
        {
          id: `e-${transitionId}->${transition.to}`,
          type: 'transition',
          source: transitionId,
          target: transition.to,
          markerEnd: { type: MarkerType.ArrowClosed, color: edgeStyle.stroke },
        },
      ];
    });

    // Add placeholder nodes for last statu
    const placeholderNodes: Node[] = workflowDefinition.states.slice(-1).map((status) => {
      return {
        id: `placeholder-${status.name}`,
        type: 'placeholder',
        data: {},
        position: { x: 0, y: 0 },
      };
    });

    const placeholderEdges: Edge[] = workflowDefinition.states.slice(-1).map((status) => {
      const transitionId = `placeholder-${status.name}`;

      return {
        id: `e-${status.name}->${transitionId}`,
        source: status.name,
        target: transitionId,
        markerEnd: { type: MarkerType.ArrowClosed, color: theme.palette.chip?.main },
        style: {
          strokeWidth: 0.5,
          strokeDasharray: '3 3',
          stroke: theme.palette.chip.main,
          fill: 'none',
        },
      };
    });

    return {
      initialNodes: [...stateNodes, ...transitionNodes, ...placeholderNodes],
      initialEdges: [...transitionEdges, ...placeholderEdges],
    };
  }, [theme]);

  const [nodes, _, onNodesChange] = useNodesState<Node[]>(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge[]>(initialEdges);

  const onSave = () => {
    const finalSchema = transformToWorkflowDefinition(nodes, edges, workflowDefinition);
    console.log('Saved Schema:', JSON.stringify(finalSchema, null, 2));
    // TODO mutation
    return finalSchema;
  };

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge(params, eds)),
    [setEdges],
  );

  const [selectedElement, setSelectedElement] = useState<Node | Edge | null>(null);
  const onNodeClick: NodeMouseHandler = useCallback(
    (_, node) => {
      getNode(node.id);
      console.log('Node clicked:', node);
      if (node.type === 'placeholder') {
        setSelectedElement({ ...node, source: node.id.replace('placeholder-', '') });
      }
      setSelectedElement(node);
    },
    [getNode],
  );
  const onEdgeClick = useCallback(
    (_event, edge: Edge) => {
      console.log('Edge clicked:', edge);
      const newState: Node = {
        id: edge.id,
        type: 'placeholder',
        data: { name: null, conditions: [] },
        position: { x: 0, y: 0 },
        source: edge.source,
        target: edge.target,
      };

      setSelectedElement(newState);
    },
    [],
  );

  const layoutOptions: LayoutOptions = {
    direction: 'TB' as LayoutOptions['direction'],
    spacing: [50, 50],
  };

  useWorkflowLayout(layoutOptions);

  // every time our nodes change, we want to center the graph again
  useEffect(() => {
    console.log({ nodes, edges });
    fitView();
  }, [nodes, edges, fitView]);

  return (
    <div style={{ width: '100%', height: '100%', margin: 0, overflow: 'hidden' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onConnect={onConnect}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodeClick={onNodeClick}
        onEdgeClick={onEdgeClick}
        fitView
        defaultViewport={defaultViewport}
        minZoom={0.2}
        fitViewOptions={fitViewOptions}
        nodesDraggable={false}
        // nodesConnectable={false}
        zoomOnDoubleClick={false}
        proOptions={proOptions}
      >
        <Panel position="top-right" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <Button onClick={onSave} startIcon={<SaveOutlined />} variant="secondary">
            Save
          </Button>
          <Button onClick={() => setSelectedElement({ id: 'new-status', type: 'placeholder', data: {}, position: { x: 0, y: 0 } })}>
            Add Status
          </Button>
        </Panel>
      </ReactFlow>
      {selectedElement && (
        <WorkflowEditionDrawer selectedElement={selectedElement} onClose={() => setSelectedElement(null)} />
      )}
    </div>
  );
};
export default Workflow;
