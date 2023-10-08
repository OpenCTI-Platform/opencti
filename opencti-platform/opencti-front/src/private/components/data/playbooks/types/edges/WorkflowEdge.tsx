import React from 'react';
import {
  EdgeLabelRenderer,
  EdgeProps,
  getBezierPath,
  useReactFlow,
} from 'reactflow';
import { makeStyles } from '@mui/styles';
import { Theme } from '../../../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  edgeButton: {
    cursor: 'pointer',
    pointerEvents: 'all',
    stroke: theme.palette.primary.main,
    fill: theme.palette.background.default,
    '&:hover': {
      fill: theme.palette.background.paper,
    },
  },
  edgeButtonText: {
    pointerEvents: 'none',
    userSelect: 'none',
    fill: theme.palette.primary.main,
  },
  edgePath: {
    fill: 'none',
    stroke: theme.palette.primary.main,
    strokeWidth: 1,
  },
}));

function EdgeLabel({ transform, label }: { transform: string; label: string }) {
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
      {label}
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
  const classes = useStyles();
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
      <path
        id={id}
        style={style}
        className={classes.edgePath}
        d={edgePath}
        markerEnd={markerEnd}
      />
      <g transform={`translate(${edgeCenterX}, ${edgeCenterY})`}>
        <rect
          onClick={() => data.openConfig(getEdge(id))}
          x={-10}
          y={-10}
          width={20}
          ry={4}
          rx={4}
          height={20}
          className={classes.edgeButton}
        />
        <text className={classes.edgeButtonText} y={5} x={-4}>
          +
        </text>
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
