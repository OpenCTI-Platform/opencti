import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';

const PageContainer: FunctionComponent<{ children: React.ReactNode, withRightMenu: boolean }> = ({ children, withRightMenu = false }) => {
  const theme = useTheme<Theme>();
  return (
    <div
      style={{
        margin: 0,
        padding: 0,
        paddingRight: withRightMenu ? '200px' : undefined,
        display: 'flex',
        flexDirection: 'column',
        gap: theme.spacing(2),
      }}
    >
      {children}
    </div>
  );
};

export default PageContainer;
