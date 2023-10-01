import React, { memo } from 'react';
import { Handle, Position, NodeProps, useReactFlow } from 'reactflow';
import { makeStyles } from '@mui/styles';
import { Theme } from '../../../../../../components/Theme';

type node = {
  id: string;
};

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

const NodeWorkflow = ({ id, data }: NodeProps) => {
  const classes = useStyles();
  const { getNode } = useReactFlow();
  return (
    <div className={classes.node} onClick={() => data.onClick(getNode(id))}>
      <span className={classes.name}>{data.name}</span>
      {!data.component?.is_entry_point && (
        <Handle type="target" position={Position.Top} isConnectable={false} />
      )}
      {(data.component?.ports ?? []).map((n: node) => (
        <Handle
          id={n.id}
          type="source"
          position={Position.Bottom}
          isConnectable={false}
        />
      ))}
    </div>
  );
};

export default memo(NodeWorkflow);
