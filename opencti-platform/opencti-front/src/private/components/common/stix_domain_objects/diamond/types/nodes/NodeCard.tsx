import React, { memo } from 'react';
import { Handle, NodeProps, Position } from 'reactflow';
import { makeStyles } from '@mui/styles';
import Typography from '@mui/material/Typography';
import type { Theme } from '../../../../../../../components/Theme';
import { useFormatter } from '../../../../../../../components/i18n';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  node: {
    position: 'relative',
    border:
      theme.palette.mode === 'dark'
        ? '1px solid rgba(255, 255, 255, 0.12)'
        : '1px solid rgba(0, 0, 0, 0.12)',
    borderRadius: 4,
    backgroundColor: theme.palette.background.paper,
    width: 400,
    height: 400,
    padding: 20,
  },
  handle: {
    visibility: 'hidden',
  },
}));

const NodeCard = ({ data }: NodeProps) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  let position;
  switch (data.key) {
    case 'capabilities':
      position = Position.Right;
      break;
    case 'victimology':
      position = Position.Top;
      break;
    case 'adversary':
      position = Position.Bottom;
      break;
    default:
      position = Position.Left;
  }
  return (
    <div className={classes.node}>
      <Typography variant="h3" gutterBottom={true}>
        {t_i18n('Type')}
      </Typography>
      <Handle
        className={classes.handle}
        type="target"
        position={position}
        isConnectable={false}
      />
    </div>
  );
};

export default memo(NodeCard);
