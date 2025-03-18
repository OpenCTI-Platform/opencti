import Drawer from '@mui/material/Drawer';
import React from 'react';
import Divider from '@mui/material/Divider';
import { useTheme } from '@mui/material/styles';
import LinearProgress from '@mui/material/LinearProgress';
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
import GraphToolbarExpandTools, { GraphToolbarExpandToolsProps } from './components/GraphToolbarExpandTools';

export type GraphToolbarProps = GraphToolbarContentToolsProps & GraphToolbarExpandToolsProps;

const GraphToolbar = ({
  onInvestigationExpand,
  onInvestigationRollback,
  ...props
}: GraphToolbarProps) => {
  const theme = useTheme<Theme>();
  const navOpen = localStorage.getItem('navOpen') === 'true';
  const { selectBySearch } = useGraphInteractions();

  const {
    graphState: {
      showTimeRange,
      showLinearProgress,
      loadingCurrent,
      loadingTotal,
      search,
    },
    context,
  } = useGraphContext();

  const isLoadingData = (loadingCurrent ?? 0) < (loadingTotal ?? 0);

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
      <LinearProgress
        style={{
          width: '100%',
          height: 2,
          position: 'absolute',
          top: -1,
          visibility: showLinearProgress || isLoadingData ? 'visible' : 'hidden',
        }}
      />
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
          {context !== 'analyses' && (
            <SearchInput
              keyword={search ?? ''}
              variant="thin"
              onSubmit={selectBySearch}
            />
          )}
        </div>

        {context === 'investigation' && (
          <>
            <Divider sx={{ margin: 1, height: '80%' }} orientation="vertical" />
            <GraphToolbarExpandTools
              onInvestigationExpand={onInvestigationExpand}
              onInvestigationRollback={onInvestigationRollback}
            />
            <Divider sx={{ margin: 1, height: '80%' }} orientation="vertical" />
          </>
        )}

        {context !== 'analyses' && <GraphToolbarContentTools {...props} />}
      </div>

      <GraphToolbarTimeRange />
    </Drawer>
  );
};

export default GraphToolbar;
