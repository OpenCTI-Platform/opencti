import React from 'react';
import { BaseEdge, EdgeLabelRenderer, EdgeProps, getBezierPath } from 'reactflow';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../../components/Theme';

function EdgeLabel({ transform, label }: { transform: string; label: string }) {
  const theme = useTheme<Theme>();
  return (
    <div
      style={{
        position: 'absolute',
        background: 'transparent',
        backgroundColor: theme.palette.background.paper,
        border: `1px solid ${theme.palette.primary.main}`,
        borderRadius: 4,
        padding: 8,
        fontSize: 12,
        transform,
      }}
      className="nodrag nopan"
    >
      {label}
    </div>
  );
}

export default function CustomEdge({
  id, sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  markerEnd,
  data,
}: EdgeProps) {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });
  return (
    <>
      <BaseEdge id={id} path={edgePath} markerEnd={markerEnd} style={style} />
      <EdgeLabelRenderer>
        <EdgeLabel label={data.label} transform={`translate(-50%, -50%) translate(${labelX}px,${labelY}px)`} />
      </EdgeLabelRenderer>
    </>
  );
}
