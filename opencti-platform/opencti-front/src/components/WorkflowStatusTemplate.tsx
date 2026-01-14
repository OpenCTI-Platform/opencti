import React, { memo, useCallback, useMemo } from 'react';
import Chip from '@mui/material/Chip';
import { ArrowRightAltOutlined } from '@mui/icons-material';
import Box from '@mui/material/Box';
import { useFormatter } from './i18n';
import { hexToRGB } from '../utils/Colors';
import 'reactflow/dist/style.css';
import ReactFlow, { addEdge, applyEdgeChanges, BaseEdge, Connection, EdgeProps, getBezierPath, Handle, MarkerType, NodeProps, Position, ReactFlowProvider, useEdgesState, useNodesState, useReactFlow } from 'reactflow';
import { ErrorBoundary } from '@components/Error';
import { useTheme } from '@mui/styles';

export interface StatusTemplateType {
  id: string;
  color: string;
  name: string;
}

export interface StatusType {
  template: StatusTemplateType;
  id: string;
  order: number;
}

interface WorkflowStatusTemplateProps {
  statuses: StatusType[];
  disabled: boolean;
}

const defaultViewport = { x: 0, y: 0, zoom: 1.5 };
const proOptions = { account: 'paid-pro', hideAttribution: true };
const fitViewOptions = { padding: 0.1 };
const defaultEdgeOptions = {
  type: 'straight',
  markerEnd: { type: MarkerType.Arrow },
  style: { strokeWidth: 2, strokeDasharray: '3 3' },
};

const NodeStatus = memo(({ id, data }: NodeProps) => {
  const { t_i18n } = useFormatter();
  return (
    <>
      <Handle
        id="source"
        type="source"
        position={Position.Right}
      />
      <Handle
        id="target"
        type="target"
        position={Position.Left}
      />
      <Chip
        key={id}
        style={{
          fontSize: 12,
          lineHeight: '12px',
          height: 50,
          textTransform: 'uppercase',
          borderRadius: 4,
          backgroundColor: hexToRGB(data.color),
          color: data.color,
          border: `1px solid ${data.color}`,
          minWidth: 100,
        }}
        variant="outlined"
        label={data.label.toUpperCase().replace(/_/g, ' ')}
      />
    </>
  );
})

const EdgeRelationship = memo(({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style,
  markerEnd,
  data,
}: EdgeProps) => {
  console.log('Rendering EdgeRelationship', id, data);
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const [edgePath, edgeCenterX, edgeCenterY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });
  return (
    <path
      id={id}
      style={{
        ...style,
        strokeWidth: 0.5,
        strokeDasharray: '3 3',
        stroke: theme.palette.chip.main,
        fill: 'none',
      }}
      d={edgePath}
      markerEnd={markerEnd}
    />
    // <BaseEdge id={id} path={edgePath} markerEnd={markerEnd} style={style} />
  );
  return (
    <path
      id={id}
      style={{
        fill: 'none',
        stroke: theme.palette.primary.main,
        strokeWidth: 1,
      }}
      d={edgePath}
      markerEnd={markerEnd}
    />
  );
})

const nodeTypes = { status: NodeStatus };
const edgeTypes = { custom: EdgeRelationship };

const WorkflowStatusTemplate = ({ statuses, disabled }: WorkflowStatusTemplateProps) => {
  const initialNodes = useMemo(() => statuses.map((status, index) => ({
    id: status.template.name,
    type: 'status',
    position: { x: index * 200, y: 0 },
    data: { label: status.template.name, color: status.template.color },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
  })), [statuses]);

  const initialEdges = useMemo(() => statuses.slice(1).map((status, index) => ({
    id: `e${statuses[index].template.name}->${status.template.name}`,
    markerEnd: { type: MarkerType.ArrowClosed },
    source: statuses[index].template.name,
    target: status.template.name,
  })), [statuses]);

  const Flow = () => {
    const [nodes, _, onNodesChange] = useNodesState(initialNodes);
    const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

    const onConnect = useCallback(
      (params: Connection) => setEdges((eds) => addEdge(params, eds)),
      [setEdges],
    );
    return (
      <>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onConnect={onConnect}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          fitView={true}
          fitViewOptions={fitViewOptions}
          defaultViewport={defaultViewport}
          // defaultEdgeOptions={defaultEdgeOptions}
          // nodesDraggable={false}
          // nodesConnectable={true}
          proOptions={proOptions}
          preventScrolling={false}
          zoomOnScroll={false}

        />
      </>
    );
  };
  return (
    <>
      <ErrorBoundary>
        <div id="container">
          <div
            style={{
              margin: 0,
              overflow: 'hidden',
              width: '100%',
              height: 200,
            }}
          >
            <ReactFlowProvider>
              <Flow />
            </ReactFlowProvider>
          </div>
        </div>
      </ErrorBoundary>
    </>
  );
};
export default WorkflowStatusTemplate;
