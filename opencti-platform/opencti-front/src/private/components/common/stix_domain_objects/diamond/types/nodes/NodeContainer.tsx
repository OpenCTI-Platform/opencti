import React, { FunctionComponent, ReactNode } from 'react';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import { Link } from 'react-router-dom';
import { Handle, Position } from 'reactflow';
import { useFormatter } from 'src/components/i18n';
import type { Theme } from '../../../../../../../components/Theme';

interface NodeContainerProps {
  children: ReactNode;
  height?: number;
  link: string;
  position: Position;
}

const NodeContainer: FunctionComponent<NodeContainerProps> = ({
  children,
  height = 300,
  link,
  position,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  return (
    <div style={{
      position: 'relative',
      border: theme.palette.mode === 'dark'
        ? '1px solid rgba(255, 255, 255, 0.12)'
        : '1px solid rgba(0, 0, 0, 0.12)',
      borderRadius: '4px',
      backgroundColor: theme.palette.background.paper,
      width: '400px',
      height: `${height}px`,
      paddingBottom: '25px',
    }}
    >
      <div style={{
        width: '100%',
        height: '100%',
        overflowY: 'auto',
        padding: '20px',
      }}
      >
        {children}
      </div>
      <Button
        component={Link}
        to={link}
        size="small"
        sx={{
          position: 'absolute',
          left: 0,
          bottom: 0,
          width: '100%',
          height: '25px',
          color: theme.palette.primary.main,
          borderTopLeftRadius: 0,
          borderTopRightRadius: 0,
          backgroundColor:
            theme.palette.mode === 'dark'
              ? 'rgba(255, 255, 255, .1)'
              : 'rgba(0, 0, 0, .1)',
          '&:hover': {
            backgroundColor:
              theme.palette.mode === 'dark'
                ? 'rgba(255, 255, 255, .2)'
                : 'rgba(0, 0, 0, .2)',
          },
        }}
        className="nodrag nopan"
      >
        {t_i18n('View all')}
      </Button>
      <Handle
        style={{ visibility: 'hidden' }}
        type="target"
        position={position}
        isConnectable={false}
      />
    </div>
  );
};

export default NodeContainer;
