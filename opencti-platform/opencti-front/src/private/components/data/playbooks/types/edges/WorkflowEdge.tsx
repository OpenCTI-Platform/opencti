import React from 'react';
import { EdgeLabelRenderer, EdgeProps, getBezierPath, useReactFlow } from 'reactflow';
import { styled } from '@mui/material/styles';
import { useFormatter } from 'src/components/i18n';

const EdgeButton = styled('rect')(({ theme }) => ({
  cursor: 'pointer',
  pointerEvents: 'all',
  stroke: theme.palette.primary.main,
  fill: theme.palette.background.default,
  '&:hover': {
    fill: theme.palette.background.paper,
  },
}));

const EdgeButtonText = styled('text')(({ theme }) => ({
  pointerEvents: 'none',
  userSelect: 'none',
  fill: theme.palette.primary.main,
}));

const EdgePath = styled('path')(({ theme }) => ({
  fill: 'none',
  stroke: theme.palette.primary.main,
  strokeWidth: 1,
}));

function EdgeLabel({ transform, label }: { transform: string; label: string }) {
  const { t_i18n } = useFormatter();
  return (
    <div
      style={{
        position: 'absolute',
        background: 'transparent',
        padding: 8,
        fontSize: 9,
        transform,
        fontFamily: 'Consolas',
      }}
      className="nodrag nopan"
    >
      {t_i18n(label)}
    </div>
  );
}

export default function CustomEdge({
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
  sourceHandleId,
}: EdgeProps) {
  const { getEdge } = useReactFlow();
  const [edgePath, edgeCenterX, edgeCenterY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });
  return (
    <>
      <EdgePath
        id={id}
        style={style}
        d={edgePath}
        markerEnd={markerEnd}
      />
      <g transform={`translate(${edgeCenterX}, ${edgeCenterY})`}>
        <EdgeButton
          onClick={() => data.openConfig(getEdge(id))}
          x={-10}
          y={-10}
          width={20}
          ry={4}
          rx={4}
          height={20}
        />
        <EdgeButtonText y={5} x={-4}>
          +
        </EdgeButtonText>
      </g>
      <EdgeLabelRenderer>
        {sourceHandleId && (
          <EdgeLabel
            transform={`translate(-50%, 0%) translate(${sourceX}px,${sourceY}px)`}
            label={sourceHandleId}
          />
        )}
      </EdgeLabelRenderer>
    </>
  );
}
