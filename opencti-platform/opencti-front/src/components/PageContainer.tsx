import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';

export const PageContainerContext = React.createContext({ inPageContainer: false });

const PageContainer: FunctionComponent<{ children: React.ReactNode, withRightMenu?: boolean, withGap?: boolean }> = ({ children, withRightMenu = false, withGap = false }) => {
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
          gap: withGap ? theme.spacing(2) : undefined,
        }}
      >
        {children}
      </div>
    </PageContainerContext.Provider>
  );
};

export default PageContainer;
