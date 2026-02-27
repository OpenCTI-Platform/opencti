import { Handle, NodeProps, Position } from 'reactflow';
import { hexToRGB } from '../../../../../../utils/Colors';
import { Chip } from '@mui/material';
import { NODE_SIZE } from '../utils';

const StatusNode = ({ id, data }: NodeProps) => {
  const { name, color } = data.statusTemplate;
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
          backgroundColor: hexToRGB(color),
          color: color,
          border: `1px solid ${color}`,
          minWidth: NODE_SIZE.width,
          cursor: 'pointer',
        }}
        variant="outlined"
        label={name}
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
