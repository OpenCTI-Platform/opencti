import React, { CSSProperties, useRef } from 'react';
import { useTheme } from '@mui/material/styles';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import type { Theme } from '../../../../components/Theme';
import Graph from '../../../../utils/graph/Graph';

const ReportKnowledgeGraph = () => {
  const ref = useRef(null);
  const theme = useTheme<Theme>();
  const bannerHeight = useSettingsMessagesBannerHeight();

  const headerHeight = 64;
  const paddingHeight = 25;
  const breadcrumbHeight = 38;
  const titleHeight = 44;
  const tabsHeight = 72;
  const totalHeight = bannerHeight + headerHeight + paddingHeight + breadcrumbHeight + titleHeight + tabsHeight;
  const graphContainerStyle: CSSProperties = {
    margin: `0 -${theme.spacing(3)}`,
    height: `calc(100vh - ${totalHeight}px)`,
  };

  return (
    <div style={graphContainerStyle} ref={ref}>
      <Graph containerRef={ref} />
    </div>
  );
};

export default ReportKnowledgeGraph;
