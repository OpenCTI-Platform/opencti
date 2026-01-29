import React from 'react';
import { EdgeProps, getBezierPath } from 'reactflow';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../components/Theme';

const TransitionEdge = ({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  markerEnd,
}: EdgeProps) => {
  const theme = useTheme<Theme>();
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
      <g transform={`translate(${edgeCenterX}, ${edgeCenterY})`}>
        <rect
          x={-10}
          y={-10}
          width={20}
          ry={4}
          rx={4}
          height={20}
          style={{
            cursor: 'pointer',
            pointerEvents: 'all',
            stroke: theme.palette.primary.main,
            fill: theme.palette.background.default,
          }}
        />
        <text
          y={5}
          x={-4}
          style={{
            pointerEvents: 'none',
            userSelect: 'none',
            fill: theme.palette.primary.main,
          }}
        >
          +
        </text>
      </g>
    </>
  );
};

export default TransitionEdge;
