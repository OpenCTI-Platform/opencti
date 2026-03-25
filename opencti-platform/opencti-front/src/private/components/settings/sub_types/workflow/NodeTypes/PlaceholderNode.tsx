import { useState } from 'react';
import { Handle, NodeProps, Position } from 'reactflow';
import { Chip } from '@mui/material';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../components/Theme';
import { NODE_SIZE } from '../utils';

const PlaceholderNode = ({ id }: NodeProps) => {
  const theme = useTheme<Theme>();
  const [isHover, setIsHover] = useState(false);

  return (
    <>
      <Handle
        id="target"
        type="target"
        position={Position.Top}
        style={{ top: -2.5, visibility: 'hidden' }}
      />
      <Chip
        key={id}
        style={{
          fontSize: 12,
          height: NODE_SIZE.height,
          borderRadius: 4,
          backgroundColor: theme.palette.mode === 'dark'
            ? 'rgba(255, 255, 255, 0.04)'
            : 'rgba(0, 0, 0, 0.04)',
          color: theme.palette.mode === 'dark'
            ? `rgba(255, 255, 255, ${isHover ? 0.2 : 0.04})`
            : `rgba(0, 0, 0, ${isHover ? 0.2 : 0.04})`,

          border: theme.palette.mode === 'dark'
            ? `1px dashed rgba(255, 255, 255, ${isHover ? 0.2 : 0.05})`
            : `1px dashed rgba(0, 0, 0, ${isHover ? 0.2 : 0.05})`,
          minWidth: NODE_SIZE.width,
          cursor: 'pointer',
          textAlign: 'center',
        }}
        variant="outlined"
        label="+"
        onMouseEnter={() => setIsHover(true)}
        onMouseLeave={() => setIsHover(false)}
      />
    </>
  );
};

export default PlaceholderNode;
