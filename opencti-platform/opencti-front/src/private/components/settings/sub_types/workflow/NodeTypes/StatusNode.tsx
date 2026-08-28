import { Handle, NodeProps, Position } from 'reactflow';
import { useTheme } from '@mui/material';
import { Chip } from '@filigran/design-system';
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
        color={color}
        style={{
          fontSize: 12,
          height: NODE_SIZE.height,
          textTransform: 'uppercase',
          borderRadius: 4,
          minWidth: NODE_SIZE.width,
          cursor: 'pointer',
          position: 'relative',
        }}
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
