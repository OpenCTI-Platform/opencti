import { memo, ReactNode } from 'react';
import SourcesNumber from '@components/common/sources/SourcesNumber';
import SourcesDistribution from '@components/common/sources/SourcesDistribution';
import SourcesTimeSeries from '@components/common/sources/SourcesTimeSeries';
import SourcesBubble from '@components/common/sources/SourcesBubble';
import type { Widget, WidgetHost } from '../../utils/widget/widget';
import type { DashboardConfig } from './dashboard-types';
import WidgetNotImplemented from './WidgetNotImplemented';

interface DashboardSourcesVizProps {
  widget: Widget;
  popover?: ReactNode;
  config: DashboardConfig;
  host?: WidgetHost;
  refreshRate?: number | null;
}

/**
 * Widgets of the "Intelligence sources" perspective, computed from the Source Intelligence scorecards.
 */
const DashboardSourcesViz = ({ widget, popover, config, host, refreshRate }: DashboardSourcesVizProps) => {
  const common = {
    dataSelection: widget.dataSelection,
    parameters: widget.parameters ?? {},
    popover,
    host,
    config,
    refreshRate,
  };
  switch (widget.type) {
    case 'number':
      return <SourcesNumber {...common} />;
    case 'list':
    case 'distribution-list':
    case 'horizontal-bar':
    case 'donut':
      return <SourcesDistribution widgetType={widget.type} {...common} />;
    case 'line':
      return <SourcesTimeSeries {...common} />;
    case 'bubble':
      return <SourcesBubble {...common} />;
    default:
      return <WidgetNotImplemented popover={popover} />;
  }
};

export default memo(DashboardSourcesViz);
