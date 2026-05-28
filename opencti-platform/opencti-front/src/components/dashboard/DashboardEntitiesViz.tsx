import { memo, ReactNode } from 'react';
import StixDomainObjectBookmarksList from '../../private/components/common/stix_domain_objects/StixDomainObjectBookmarksList';
import StixCoreObjectsNumber from '../../private/components/common/stix_core_objects/StixCoreObjectsNumber';
import StixCoreObjectsList from '@components/common/stix_core_objects/StixCoreObjectsList';
import StixCoreObjectsDistributionList from '../../private/components/common/stix_core_objects/StixCoreObjectsDistributionList';
import StixCoreObjectsMultiVerticalBars from '../../private/components/common/stix_core_objects/StixCoreObjectsMultiVerticalBars';
import StixCoreObjectsMultiLineChart from '../../private/components/common/stix_core_objects/StixCoreObjectsMultiLineChart';
import StixCoreObjectsMultiAreaChart from '../../private/components/common/stix_core_objects/StixCoreObjectsMultiAreaChart';
import StixCoreObjectsTimeline from '@components/common/stix_core_objects/StixCoreObjectsTimeline';
import StixCoreObjectsDonut from '../../private/components/common/stix_core_objects/StixCoreObjectsDonut';
import StixCoreObjectsPolarArea from '@components/common/stix_core_objects/StixCoreObjectsPolarArea';
import StixCoreObjectsMultiHorizontalBars from '../../private/components/common/stix_core_objects/StixCoreObjectsMultiHorizontalBars';
import StixCoreObjectsHorizontalBars from '../../private/components/common/stix_core_objects/StixCoreObjectsHorizontalBars';
import StixCoreObjectsRadar from '../../private/components/common/stix_core_objects/StixCoreObjectsRadar';
import StixCoreObjectsMultiHeatMap from '../../private/components/common/stix_core_objects/StixCoreObjectsMultiHeatMap';
import StixCoreObjectsTreeMap from '../../private/components/common/stix_core_objects/StixCoreObjectsTreeMap';
import StixCoreObjectsWordCloud from '@components/common/stix_core_objects/StixCoreObjectsWordCloud';
import type { Widget, WidgetHost } from '../../utils/widget/widget';
import { computeRelativeDate, dayStartDate, formatDate } from '../../utils/Time';
import type { DashboardConfig } from './dashboard-types';

interface DashboardEntitiesVizProps {
  widget: Widget;
  popover?: ReactNode;
  config: DashboardConfig;
  host?: WidgetHost;
  refreshRate?: number | null;
}

const DashboardEntitiesViz = ({
  widget,
  popover,
  config,
  host,
  refreshRate,
}: DashboardEntitiesVizProps) => {
  const startDate = config.relativeDate
    ? computeRelativeDate(config.relativeDate)
    : config.startDate;

  const endDate = config.relativeDate
    ? formatDate(dayStartDate(null, false))
    : config.endDate;

  switch (widget.type) {
    case 'bookmark':
      return (
        <StixDomainObjectBookmarksList
          variant={undefined} // because calling js component in ts
          height={undefined} // because calling js component in ts
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'number':
      return (
        <StixCoreObjectsNumber
          variant={undefined}
          height={undefined}
          dataSelection={widget.dataSelection}
          entityType={undefined} // because calling js component in ts
          parameters={widget.parameters as object} // because calling js component in ts
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'list':
      return (
        <StixCoreObjectsList
          variant={undefined}
          widgetId={widget.id}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'distribution-list':
      return (
        <StixCoreObjectsDistributionList
          variant={undefined}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'vertical-bar':
      return (
        <StixCoreObjectsMultiVerticalBars
          variant={undefined}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'line':
      return (
        <StixCoreObjectsMultiLineChart
          variant={undefined}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'area':
      return (
        <StixCoreObjectsMultiAreaChart
          variant={undefined}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'timeline':
      return (
        <StixCoreObjectsTimeline
          variant={undefined}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'donut':
      return (
        <StixCoreObjectsDonut
          variant={undefined}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined}
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'polar-area':
      return (
        <StixCoreObjectsPolarArea
          variant={undefined}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters}
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'horizontal-bar':
      if (
        widget.dataSelection.length > 1
        && widget.dataSelection[0].attribute?.endsWith('_id')
      ) {
        return (
          <StixCoreObjectsMultiHorizontalBars
            variant={undefined}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters as object} // because calling js component in ts
            height={undefined} // because calling js component in ts
            popover={popover}
            host={host}
            refreshRate={refreshRate}
            config={config}
          />
        );
      }
      return (
        <StixCoreObjectsHorizontalBars
          variant={undefined}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'radar':
      return (
        <StixCoreObjectsRadar
          variant={undefined}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'heatmap':
      return (
        <StixCoreObjectsMultiHeatMap
          variant={undefined}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'tree':
      return (
        <StixCoreObjectsTreeMap
          variant={undefined}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'wordcloud':
      return (
        <StixCoreObjectsWordCloud
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined}
          popover={popover}
          host={host}
        />
      );
    default:
      return 'Not implemented yet';
  }
};

export default memo(DashboardEntitiesViz);
