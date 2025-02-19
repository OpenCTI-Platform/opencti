import Drawer from '@mui/material/Drawer';
import React from 'react';
import Divider from '@mui/material/Divider';
import { useTheme } from '@mui/material/styles';
import useGraphInteractions from '../utils/useGraphInteractions';
import SearchInput from '../../../components/SearchInput';
import type { Theme } from '../../../components/Theme';
import GraphToolbarDisplayTools from './GraphToolbarDisplayTools';
import GraphToolbarSelectTools from './GraphToolbarSelectTools';
import GraphToolbarFilterTools from './GraphToolbarFilterTools';
import GraphToolbarContentTools, { GraphToolbarContentToolsProps } from './GraphToolbarContentTools';

export type GraphToolbarProps = GraphToolbarContentToolsProps;

const GraphToolbar = (props: GraphToolbarProps) => {
  const theme = useTheme<Theme>();
  const navOpen = localStorage.getItem('navOpen') === 'true';

  const {
    selectBySearch,
  } = useGraphInteractions();

  return (
    <Drawer
      anchor="bottom"
      variant="permanent"
      PaperProps={{
        elevation: 1,
        style: {
          zIndex: 1,
          paddingLeft: navOpen ? 180 : 60,
          height: 54,
        },
      }}
    >
      <div style={{
        height: 54,
        display: 'flex',
        alignItems: 'center',
        gap: theme.spacing(0.5),
        padding: `0 ${theme.spacing(0.5)}`,
      }}
      >
        <GraphToolbarDisplayTools />
        <Divider sx={{ margin: 1, height: '80%' }} orientation="vertical" />

        <GraphToolbarSelectTools />
        <Divider sx={{ margin: 1, height: '80%' }} orientation="vertical" />

        <GraphToolbarFilterTools />
        <Divider sx={{ margin: 1, marginRight: 3, height: '80%' }} orientation="vertical" />

        <div style={{ flex: 1 }}>
          <SearchInput variant="thin" onSubmit={selectBySearch} />
        </div>

        <GraphToolbarContentTools {...props} />
      </div>
    </Drawer>
  );
};

export default GraphToolbar;
