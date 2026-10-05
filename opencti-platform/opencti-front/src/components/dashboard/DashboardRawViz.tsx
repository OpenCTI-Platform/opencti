import { memo, ReactNode } from 'react';
import WidgetText from './WidgetText';
import type { Widget, WidgetHost } from 'src/utils/widget/widget';
import StixCoreObjectsCustomAttributes from '@components/common/stix_core_objects/StixCoreObjectsCustomAttributes';
import KnowledgeHealthWidget from '@components/data/curation/KnowledgeHealthWidget';
import type { DashboardConfig } from './dashboard-types';
import { computeStartEndDates } from 'src/components/dashboard/dashboardVizUtils';
import WidgetNotImplemented from './WidgetNotImplemented';
import WidgetDefenseTacticCoverage from '@components/defense/matrix/widgets/WidgetDefenseTacticCoverage';
import WidgetDefenseTopGaps from '@components/defense/matrix/widgets/WidgetDefenseTopGaps';
import WidgetDefenseLevels from '@components/defense/matrix/widgets/WidgetDefenseLevels';
import WidgetHuntStatistics from '@components/hunts/widgets/WidgetHuntStatistics';

interface DashboardRawVizProps {
  widget: Widget;
  popover?: ReactNode;
  config?: DashboardConfig;
  host?: WidgetHost;
}

const DashboardRawViz = ({
  widget,
  popover,
  config,
  host,
}: DashboardRawVizProps) => {
  const { startDate, endDate } = computeStartEndDates(config);

  switch (widget.type) {
    case 'text':
      return (
        <WidgetText
          parameters={widget.parameters}
          popover={popover}
        />
      );
    case 'defense-tactic-coverage':
      return <WidgetDefenseTacticCoverage title={widget.parameters?.title} popover={popover} />;
    case 'defense-top-gaps':
      return <WidgetDefenseTopGaps title={widget.parameters?.title} popover={popover} />;
    case 'defense-levels':
      return <WidgetDefenseLevels title={widget.parameters?.title} popover={popover} />;
    case 'hunt-hits-over-time':
    case 'hunt-runs-per-platform':
    case 'hunt-verdict-distribution':
      return (
        <WidgetHuntStatistics
          type={widget.type}
          title={widget.parameters?.title}
          startDate={startDate}
          endDate={endDate}
          popover={popover}
        />
      );
    case 'custom-attributes':
      return (
        <StixCoreObjectsCustomAttributes
          variant={undefined}
          height={undefined}
          endDate={endDate ?? undefined}
          startDate={startDate ?? undefined}
          widgetId={widget.id}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as Record<string, unknown>}
          title={undefined}
          popover={popover}
          host={host}
        />
      );
    case 'knowledge-health-score':
    case 'knowledge-health-trend':
    case 'curation-open-proposals':
      return (
        <KnowledgeHealthWidget
          variant={widget.type}
          title={widget.parameters?.title}
          popover={popover}
        />
      );
    default:
      return (
        <WidgetNotImplemented popover={popover} />
      );
  }
};

export default memo(DashboardRawViz);
