import { memo, ReactNode } from 'react';
import AuditsNumber from '@components/common/audits/AuditsNumber';
import AuditsList from '@components/common/audits/AuditsList';
import AuditsDistributionList from '@components/common/audits/AuditsDistributionList';
import AuditsMultiVerticalBars from '@components/common/audits/AuditsMultiVerticalBars';
import AuditsMultiLineChart from '@components/common/audits/AuditsMultiLineChart';
import AuditsMultiAreaChart from '@components/common/audits/AuditsMultiAreaChart';
import AuditsDonut from '@components/common/audits/AuditsDonut';
import AuditsPolarArea from '@components/common/audits/AuditsPolarArea';
import AuditsHorizontalBars from '@components/common/audits/AuditsHorizontalBars';
import AuditsRadar from '@components/common/audits/AuditsRadar';
import AuditsMultiHeatMap from '@components/common/audits/AuditsMultiHeatMap';
import AuditsTreeMap from '@components/common/audits/AuditsTreeMap';
import AuditsWordCloud from '@components/common/audits/AuditsWordCloud';
import { computeRelativeDate, dayStartDate, formatDate } from '../../utils/Time';
import type { Widget, WidgetHost } from '../../utils/widget/widget';
import type { DashboardConfig } from './dashboard-types';

interface DashboardAuditsVizProps {
  widget: Widget;
  popover?: ReactNode;
  config: DashboardConfig;
  host?: WidgetHost;
  refreshRate?: number | null;
}

const DashboardAuditsViz = ({
  widget,
  popover,
  config,
  host,
  refreshRate,
}: DashboardAuditsVizProps) => {
  const startDate = config.relativeDate
    ? computeRelativeDate(config.relativeDate)
    : config.startDate;

  const endDate = config.relativeDate
    ? formatDate(dayStartDate(null, false))
    : config.endDate;

  switch (widget.type) {
    case 'number':
      return (
        <AuditsNumber
          variant={undefined}
          height={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          entityType={undefined} // because calling js component in ts
          parameters={widget.parameters as object} // because calling js component in ts
          popover={popover}
          host={host}
          config={config}
          refreshRate={refreshRate}
        />
      );
    case 'list':
      return (
        <AuditsList
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          config={config}
          refreshRate={refreshRate}
        />
      );
    case 'distribution-list':
      return (
        <AuditsDistributionList
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          config={config}
          refreshRate={refreshRate}
        />
      );
    case 'vertical-bar':
      return (
        <AuditsMultiVerticalBars
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          config={config}
          refreshRate={refreshRate}
        />
      );
    case 'line':
      return (
        <AuditsMultiLineChart
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          config={config}
          refreshRate={refreshRate}
        />
      );
    case 'area':
      return (
        <AuditsMultiAreaChart
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          config={config}
          refreshRate={refreshRate}
        />
      );
    case 'donut':
      return (
        <AuditsDonut
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          config={config}
          refreshRate={refreshRate}
        />
      );
    case 'polar-area':
      return (
        <AuditsPolarArea
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          config={config}
          refreshRate={refreshRate}
        />
      );
    case 'horizontal-bar':
      return (
        <AuditsHorizontalBars
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          config={config}
          refreshRate={refreshRate}
        />
      );
    case 'radar':
      return (
        <AuditsRadar
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          config={config}
          refreshRate={refreshRate}
        />
      );
    case 'heatmap':
      return (
        <AuditsMultiHeatMap
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          config={config}
          refreshRate={refreshRate}
        />
      );
    case 'tree':
      return (
        <AuditsTreeMap
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          config={config}
          refreshRate={refreshRate}
        />
      );
    case 'wordcloud':
      return (
        <AuditsWordCloud
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          config={config}
          refreshRate={refreshRate}
        />
      );
    default:
      return 'Not implemented yet';
  }
};

export default memo(DashboardAuditsViz);
