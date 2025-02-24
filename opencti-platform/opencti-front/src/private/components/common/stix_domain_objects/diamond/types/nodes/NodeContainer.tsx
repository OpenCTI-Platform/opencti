import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../../components/Theme';

interface NodeContainerProps {
  content: React.ReactNode;
}

const NodeContainer: FunctionComponent<NodeContainerProps> = ({ content }) => {
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
      height: '300px',
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
        {content}
      </div>
    </div>
  );
};

export default NodeContainer;
