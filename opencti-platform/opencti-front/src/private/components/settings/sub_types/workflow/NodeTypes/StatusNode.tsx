import React from 'react';
import { Handle, NodeProps, Position } from 'reactflow';
import { hexToRGB } from '../../../../../../utils/Colors';
import { Chip } from '@mui/material';
import { NODE_SIZE } from '../utils';

const StatusNode = ({ id, data }: NodeProps) => {
  return (
    <>
      <Handle
        id="target"
        type="target"
        position={Position.Top}
        style={{ top: -2.5 }}
      />
      <Chip
        key={id}
        style={{
          fontSize: 12,
          height: NODE_SIZE.height,
          textTransform: 'uppercase',
          borderRadius: 4,
          backgroundColor: hexToRGB(data.color),
          color: data.color,
          border: `1px solid ${data.color}`,
          minWidth: NODE_SIZE.width,
          cursor: 'pointer',
        }}
        variant="outlined"
        label={data.name.toUpperCase().replace(/_/g, ' ')}
      />
      <Handle
        id="source"
        type="source"
        position={Position.Bottom}
        style={{ bottom: -2.5 }}
      />
    </>
  );
};

export default StatusNode;
