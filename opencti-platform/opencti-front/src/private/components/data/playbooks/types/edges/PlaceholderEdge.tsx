import React from 'react';
import { EdgeLabelRenderer, EdgeProps, getBezierPath } from 'reactflow';
import { useFormatter } from 'src/components/i18n';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../components/Theme';

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

export default function PlaceholderEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style,
  markerEnd,
  sourceHandleId,
}: EdgeProps) {
  const theme = useTheme<Theme>();
  const [edgePath] = getBezierPath({
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
          ...style,
          strokeWidth: 0.5,
          strokeDasharray: '3 3',
          stroke: theme.palette.chip.main,
          fill: 'none',
        }}
        d={edgePath}
        markerEnd={markerEnd}
      />
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
