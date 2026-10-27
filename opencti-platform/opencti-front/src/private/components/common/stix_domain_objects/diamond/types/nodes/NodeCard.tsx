import React, { memo } from 'react';
import { Handle, NodeProps, Position } from 'reactflow';
import { styled } from '@mui/material/styles';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../../../../components/i18n';

const Node = styled('div')(({ theme }) => ({
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
}));

const HiddenHandle = styled(Handle)({
  visibility: 'hidden',
});

const NodeCard = ({ data }: NodeProps) => {
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
    <Node>
      <Typography variant="h3" gutterBottom={true}>
        {t_i18n('Type')}
      </Typography>
      <HiddenHandle
        type="target"
        position={position}
        isConnectable={false}
      />
    </Node>
  );
};

export default memo(NodeCard);
