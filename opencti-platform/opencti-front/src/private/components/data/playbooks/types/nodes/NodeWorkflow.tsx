import React, { memo } from 'react';
import { Handle, Position, NodeProps } from 'reactflow';
import { makeStyles } from '@mui/styles';
import { Theme } from '../../../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  node: {
    border:
      theme.palette.mode === 'dark'
        ? '1px solid rgba(255, 255, 255, 0.12)'
        : '1px solid rgba(0, 0, 0, 0.12)',
    borderRadius: 4,
    backgroundColor: theme.palette.background.paper,
    padding: 12,
    width: 160,
    textAlign: 'center',
    cursor: 'pointer',
    '&:hover': {
      border:
        theme.palette.mode === 'dark'
          ? '1px solid rgba(255, 255, 255, 0.2)'
          : '1px solid rgba(0, 0, 0, 0.2)',
    },
  },
  name: {
    fontSize: 12,
  },
}));

const NodeWorkflow = ({ data }: NodeProps) => {
  const classes = useStyles();
  return (
    <div className={classes.node}>
      <span className={classes.name}>{data.name}</span>
      <Handle
        type="target"
        position={Position.Top}
        isConnectable={false}
      />
      <Handle
        type="source"
        position={Position.Bottom}
        isConnectable={false}
      />
    </div>
  );
};

export default memo(NodeWorkflow);
