import React, { memo } from 'react';
import { Handle, Position, NodeProps } from 'reactflow';
import Box from '@mui/material/Box';
import { styled } from '@mui/material/styles';
import ItemIcon from '../../../../../../../components/ItemIcon';
import { truncate } from '../../../../../../../utils/String';

const Node = styled('div')(({ theme }) => ({
  position: 'relative',
  width: 200,
  height: 200,
  lineHeight: '200px',
  whiteSpace: 'nowrap',
  textAlign: 'center',
  fontSize: 10,
  margin: 10,
  '&::before': {
    position: 'absolute',
    content: '""',
    top: 0,
    left: 0,
    height: '100%',
    width: '100%',
    transform: 'rotate(45deg)',
    boxShadow: '0px 0px 12px gray',
  },
  '&::after': {
    position: 'absolute',
    content: '""',
    top: 10,
    left: 10,
    height: 'calc(100% - 22px)', /* -22px is 2 * 10px gap on either side - 2px border on either side */
    width: 'calc(100% - 22px)', /* -22px is 2 * 10px gap on either side - 2px border on either side */
    border: `1px solid ${theme.palette.primary.main}`,
    transform: 'rotate(45deg)',
  },
}));

const HandleTop = styled(Handle)({
  '&&': {
    top: -50,
  },
});

const HandleRight = styled(Handle)({
  '&&': {
    right: -50,
  },
});

const HandleBottom = styled(Handle)({
  '&&': {
    bottom: -50,
  },
});

const HandleLeft = styled(Handle)({
  '&&': {
    left: -50,
  },
});

const NodeDiamond = ({ data }: NodeProps) => {
  return (
    <Node>
      {truncate(data.name, 25, false)}
      <Box sx={{ position: 'absolute', top: -85, left: 88 }}>
        <ItemIcon type="threats" />
      </Box>
      <Box sx={{ position: 'absolute', top: 10, right: -5 }}>
        <ItemIcon type="Infrastructure" />
      </Box>
      <Box sx={{ position: 'absolute', top: 110, left: 88 }}>
        <ItemIcon type="victimology" />
      </Box>
      <Box sx={{ position: 'absolute', top: 10, left: -5 }}>
        <ItemIcon type="Attack-Pattern" />
      </Box>
      <HandleTop
        id="adversary"
        type="source"
        position={Position.Top}
        isConnectable={false}
      />
      <HandleRight
        id="infrastructure"
        type="source"
        position={Position.Right}
        isConnectable={false}
      />
      <HandleBottom
        id="victimology"
        type="source"
        position={Position.Bottom}
        isConnectable={false}
      />
      <HandleLeft
        id="capabilities"
        type="source"
        position={Position.Left}
        isConnectable={false}
      />
    </Node>
  );
};

export default memo(NodeDiamond);
