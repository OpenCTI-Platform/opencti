import { Handle, NodeProps, Position } from 'reactflow';
import { hexToRGB } from '../../../../../../utils/Colors';
import { Chip, useTheme } from '@mui/material';
import { NODE_SIZE } from '../utils';
import { snakeCaseToSentenceCase } from '../../../../../../utils/String';

const StatusNode = ({ id, data }: NodeProps) => {
  const theme = useTheme();
  const { name, color } = data.statusTemplate;
  return (
    <div style={{ position: 'relative' }}>
      <div
        style={{
          position: 'absolute',
          width: '100%',
          height: '100%',
          backgroundColor: theme.palette.background.paper,
          borderRadius: 4,
        }}
      />
      <Handle
        id="target"
        type="target"
        position={Position.Top}
        style={{ top: -2.5, zIndex: 1 }}
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
          position: 'relative',
        }}
        variant="outlined"
        label={snakeCaseToSentenceCase(name)}
      />
      <Handle
        id="source"
        type="source"
        position={Position.Bottom}
        style={{ bottom: -2.5, zIndex: 1 }}
      />
    </div>
  );
};

export default StatusNode;
