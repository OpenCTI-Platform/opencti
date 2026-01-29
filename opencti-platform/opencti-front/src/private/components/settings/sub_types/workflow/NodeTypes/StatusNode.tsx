import React from 'react';
import { Handle, NodeProps, Position } from 'reactflow';
import { hexToRGB } from '../../../../../../utils/Colors';
import { Chip } from '@mui/material';

const width = 160;
const height = 50;

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
          height: height,
          textTransform: 'uppercase',
          borderRadius: 4,
          backgroundColor: hexToRGB(data.color),
          color: data.color,
          border: `1px solid ${data.color}`,
          minWidth: width,
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
