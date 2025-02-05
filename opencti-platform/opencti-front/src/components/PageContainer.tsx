import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';

export const PageContainerContext = React.createContext({ inPageContainer: false });

const PageContainer: FunctionComponent<{ children: React.ReactNode, withRightMenu: boolean }> = ({ children, withRightMenu = false }) => {
  const theme = useTheme<Theme>();
  return (
    <PageContainerContext.Provider value={{ inPageContainer: true }}>
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
    </PageContainerContext.Provider>
  );
};

export default PageContainer;
