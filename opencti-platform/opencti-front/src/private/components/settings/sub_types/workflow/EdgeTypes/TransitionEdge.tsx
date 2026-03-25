import React, { useState } from 'react';
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
  const [isHovered, setIsHovered] = useState(false);
  const [edgePath, edgeCenterX, edgeCenterY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  return (
    <g onMouseEnter={() => setIsHovered(true)} onMouseLeave={() => setIsHovered(false)}>
      <path
        id={id}
        style={{
          fill: 'none',
          stroke: theme.palette.primary.main,
          transition: 'stroke-width 0.2s',
          strokeWidth: isHovered ? 2 : 1,
        }}
        d={edgePath}
        markerEnd={markerEnd}
      />
      <path
        d={edgePath}
        fill="none"
        stroke="transparent"
        strokeWidth={20}
        style={{ cursor: 'pointer' }}
      />

      {isHovered && (
        <g transform={`translate(${edgeCenterX}, ${edgeCenterY})`} style={{ pointerEvents: 'none' }}>
          <rect
            x={-10}
            y={-10}
            width={20}
            height={20}
            ry={4}
            rx={4}
            style={{
              stroke: theme.palette.primary.main,
              fill: theme.palette.background.default,
              strokeWidth: 1,
            }}
          />
          <text
            y={5}
            x={-4}
            style={{
              userSelect: 'none',
              fill: theme.palette.primary.main,
              fontSize: '16px',
              fontWeight: 'bold',
            }}
          >
            +
          </text>
        </g>
      )}
    </g>
  );
};

export default TransitionEdge;
