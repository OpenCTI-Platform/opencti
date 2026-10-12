import { memo, ReactNode } from 'react';
import SourcesNumber from '@components/common/sources/SourcesNumber';
import SourcesDistribution from '@components/common/sources/SourcesDistribution';
import SourcesTimeSeries from '@components/common/sources/SourcesTimeSeries';
import SourcesBubble from '@components/common/sources/SourcesBubble';
import type { Widget, WidgetHost } from '../../utils/widget/widget';
import useGranted, { INGESTION, MODULES } from '../../utils/hooks/useGranted';
import { useFormatter } from '../i18n';
import type { DashboardConfig } from './dashboard-types';
import WidgetNotImplemented from './WidgetNotImplemented';
import WidgetContainer from './WidgetContainer';
import WidgetAccessDenied from './WidgetAccessDenied';

interface DashboardSourcesVizProps {
  widget: Widget;
  popover?: ReactNode;
  config: DashboardConfig;
  host?: WidgetHost;
  refreshRate?: number | null;
}

/**
 * Widgets of the "Intelligence sources" perspective, computed from the Source Intelligence scorecards.
 * Scorecards are readable with the connectors or ingestion capability: without it no source widget mounts,
 * so a viewer of a shared dashboard sends no scorecard query.
 */
const DashboardSourcesViz = ({ widget, popover, config, host, refreshRate }: DashboardSourcesVizProps) => {
  const { t_i18n } = useFormatter();
  const isGranted = useGranted([MODULES, INGESTION]);
  if (!isGranted) {
    return (
      <WidgetContainer padding="medium" title={widget.parameters?.title || t_i18n('Intelligence sources')} action={popover}>
        <WidgetAccessDenied />
      </WidgetContainer>
    );
  }
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
