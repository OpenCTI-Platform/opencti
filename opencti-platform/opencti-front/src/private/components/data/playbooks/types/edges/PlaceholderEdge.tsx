import React from 'react';
import { getBezierPath, EdgeProps } from 'reactflow';
import { makeStyles } from '@mui/styles';
import { Theme } from '../../../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  placeholderPath: {
    strokeWidth: 1,
    strokeDasharray: '3 3',
    stroke: theme.palette.chip.main,
    fill: 'none',
  },
}));

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
    <path
      id={id}
      style={style}
      className={classes.placeholderPath}
      d={edgePath}
      markerEnd={markerEnd}
    />
  );
}
