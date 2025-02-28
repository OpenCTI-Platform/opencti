import Drawer from '@mui/material/Drawer';
import React from 'react';
import Divider from '@mui/material/Divider';
import { useTheme } from '@mui/material/styles';
import useGraphInteractions from './utils/useGraphInteractions';
import SearchInput from '../../components/SearchInput';
import type { Theme } from '../../components/Theme';
import GraphToolbarDisplayTools from './components/GraphToolbarDisplayTools';
import GraphToolbarSelectTools from './components/GraphToolbarSelectTools';
import GraphToolbarFilterTools from './components/GraphToolbarFilterTools';
import GraphToolbarContentTools, { GraphToolbarContentToolsProps } from './components/GraphToolbarContentTools';
import GraphToolbarTimeRange from './components/GraphToolbarTimeRange';
import { useGraphContext } from './GraphContext';
import GraphToolbarCorrelationTools from './components/GraphToolbarCorrelationTools';
import GraphToolbarExpandTools from './components/GraphToolbarExpandTools';

export type GraphToolbarProps = GraphToolbarContentToolsProps;

const GraphToolbar = (props: GraphToolbarProps) => {
  const theme = useTheme<Theme>();
  const navOpen = localStorage.getItem('navOpen') === 'true';

  const { graphState, context } = useGraphContext();
  const { showTimeRange } = graphState;
  const { selectBySearch } = useGraphInteractions();

  return (
    <Drawer
      anchor="bottom"
      variant="permanent"
      PaperProps={{
        elevation: 1,
        style: {
          zIndex: 1,
          paddingLeft: navOpen ? 180 : 60,
          height: showTimeRange ? 134 : 54,
          overflow: 'hidden',
          transition: 'height 0.2s ease',
        },
      }}
    >
      <div style={{
        height: 54,
        flex: '0 0 auto',
        display: 'flex',
        alignItems: 'center',
        gap: theme.spacing(0.5),
        padding: `0 ${theme.spacing(1)}`,
      }}
      >
        <GraphToolbarDisplayTools />
        <Divider sx={{ margin: 1, height: '80%' }} orientation="vertical" />

        <GraphToolbarSelectTools />
        <Divider sx={{ margin: 1, height: '80%' }} orientation="vertical" />

        <GraphToolbarFilterTools />
        <Divider sx={{ margin: 1, height: '80%' }} orientation="vertical" />

        {context === 'correlation' && (
          <>
            <GraphToolbarCorrelationTools />
            <Divider sx={{ margin: 1, marginRight: 2, height: '80%' }} orientation="vertical" />
          </>
        )}

        <div style={{ flex: 1 }}>
          <SearchInput variant="thin" onSubmit={selectBySearch} />
        </div>

        {context === 'investigation' && (
          <>
            <Divider sx={{ margin: 1, height: '80%' }} orientation="vertical" />
            <GraphToolbarExpandTools />
            <Divider sx={{ margin: 1, height: '80%' }} orientation="vertical" />
          </>
        )}

        <GraphToolbarContentTools {...props} />
      </div>

      <GraphToolbarTimeRange />
    </Drawer>
  );
};

export default GraphToolbar;
