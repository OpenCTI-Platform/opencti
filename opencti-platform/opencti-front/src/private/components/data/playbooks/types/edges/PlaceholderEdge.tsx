import React from 'react';
import { getBezierPath, EdgeProps, EdgeLabelRenderer } from 'reactflow';
import { makeStyles } from '@mui/styles';
import { useFormatter } from 'src/components/i18n';
import type { Theme } from '../../../../../../components/Theme';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  placeholderPath: {
    strokeWidth: 0.5,
    strokeDasharray: '3 3',
    stroke: theme.palette.chip.main,
    fill: 'none',
  },
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
  const classes = useStyles();
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
        style={style}
        className={classes.placeholderPath}
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
