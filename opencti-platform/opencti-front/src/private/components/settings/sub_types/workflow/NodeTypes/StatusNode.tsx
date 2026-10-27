import { Handle, NodeProps, Position } from 'reactflow';
import { useTheme } from '@mui/material/styles';
import { Chip } from '@filigran/design-system';
import { hexToRGB } from '../../../../../../utils/Colors';
import { HIGHLIGHT_LABEL_SHADOW, NODE_SIZE } from '../utils';
import { snakeCaseToSentenceCase } from '../../../../../../utils/String';
import { hoverFade, useNodeHighlight } from '../hoverHighlight';

const StatusNode = ({ id, data }: NodeProps) => {
  const theme = useTheme();
  const { name, color } = data.statusTemplate;
  const { lit: highlighted, dimmed } = useNodeHighlight(id);
  return (
    <div className="workflow-status-node" style={{ position: 'relative', ...hoverFade(dimmed) }}>
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
          // Lit by a hover: a second 0.5px ring outside the border keeps the node's size unchanged.
          ...(highlighted ? { boxShadow: `0 0 0 0.5px ${color ?? 'currentColor'}`, textShadow: HIGHLIGHT_LABEL_SHADOW } : {}),
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
