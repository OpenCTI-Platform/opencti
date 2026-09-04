import { Handle, NodeProps, Position } from 'reactflow';
import { useTheme } from '@mui/material';
import { Chip } from '@filigran/design-system';
import { hexToRGB } from '../../../../../../utils/Colors';
import { NODE_SIZE } from '../utils';
import { snakeCaseToSentenceCase } from '../../../../../../utils/String';

const StatusNode = ({ id, data }: NodeProps) => {
  const theme = useTheme();
  const { name, color } = data.statusTemplate;
  return (
    <div className="workflow-status-node" style={{ position: 'relative' }}>
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
        // NOT `color`: its wash is merged over the caller's own background.
        style={{
          height: NODE_SIZE.height,
          borderRadius: 4,
          minWidth: NODE_SIZE.width,
          cursor: 'pointer',
          position: 'relative',
          // The chip starts its label and washes its border; a node is a box.
          justifyContent: 'center',
          // The label inherits it; the chip's own ink is off in the host sheet.
          ...(color ? { border: `1px solid ${color}`, color, backgroundColor: hexToRGB(color) } : {}),
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
