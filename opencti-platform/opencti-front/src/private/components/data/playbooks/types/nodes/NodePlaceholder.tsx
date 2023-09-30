import React, { memo } from 'react';
import { Handle, Position, NodeProps, useReactFlow } from 'reactflow';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '../../../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  node: {
    border:
      theme.palette.mode === 'dark'
        ? '1px dashed rgba(255, 255, 255, 0.05)'
        : '1px dashed rgba(0, 0, 0, 0.05)',
    borderRadius: 4,
    backgroundColor:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, 0.04)'
        : 'rgba(0, 0, 0, 0.04)',
    color:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, 0.04)'
        : 'rgba(0, 0, 0, 0.04)',
    padding: 12,
    width: 160,
    textAlign: 'center',
    cursor: 'pointer',
    '&:hover': {
      border:
        theme.palette.mode === 'dark'
          ? '1px dashed rgba(255, 255, 255, 0.2)'
          : '1px dashed rgba(0, 0, 0, 0.2)',
    },
  },
  handle: {
    visibility: 'hidden',
  },
}));

const NodePlaceholder = ({ id, data }: NodeProps) => {
  const classes = useStyles();
  const { getNode } = useReactFlow();
  return (
    <div className={classes.node} onClick={() => data.onClick(getNode(id))}>
      {data.name}
      <Handle
        className={classes.handle}
        type="target"
        position={Position.Top}
        isConnectable={false}
      />
      <Handle
        className={classes.handle}
        type="source"
        position={Position.Bottom}
        isConnectable={false}
      />
    </div>
  );
};

export default memo(NodePlaceholder);
