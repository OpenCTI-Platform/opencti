import { memo, ReactNode } from 'react';
import StixDomainObjectBookmarksList from '@components/common/stix_domain_objects/StixDomainObjectBookmarksList';
import StixCoreObjectsNumber from '@components/common/stix_core_objects/StixCoreObjectsNumber';
import StixCoreObjectsList from '@components/common/stix_core_objects/StixCoreObjectsList';
import StixCoreObjectsDistributionList from '@components/common/stix_core_objects/StixCoreObjectsDistributionList';
import StixCoreObjectsMultiVerticalBars from '@components/common/stix_core_objects/StixCoreObjectsMultiVerticalBars';
import StixCoreObjectsMultiLineChart from '@components/common/stix_core_objects/StixCoreObjectsMultiLineChart';
import StixCoreObjectsMultiAreaChart from '@components/common/stix_core_objects/StixCoreObjectsMultiAreaChart';
import StixCoreObjectsTimeline from '@components/common/stix_core_objects/StixCoreObjectsTimeline';
import StixCoreObjectsDonut from '@components/common/stix_core_objects/StixCoreObjectsDonut';
import StixCoreObjectsPolarArea from '@components/common/stix_core_objects/StixCoreObjectsPolarArea';
import StixCoreObjectsMultiHorizontalBars from '@components/common/stix_core_objects/StixCoreObjectsMultiHorizontalBars';
import StixCoreObjectsHorizontalBars from '@components/common/stix_core_objects/StixCoreObjectsHorizontalBars';
import StixCoreObjectsRadar from '@components/common/stix_core_objects/StixCoreObjectsRadar';
import StixCoreObjectsMultiHeatMap from '@components/common/stix_core_objects/StixCoreObjectsMultiHeatMap';
import StixCoreObjectsTreeMap from '@components/common/stix_core_objects/StixCoreObjectsTreeMap';
import StixCoreObjectsWordCloud from '@components/common/stix_core_objects/StixCoreObjectsWordCloud';
import type { Widget, WidgetHost } from '../../utils/widget/widget';
import { computerRelativeDate, dayStartDate, formatDate } from '../../utils/Time';
import type { DashboardConfig } from './dashboard-types';

interface DashboardEntitiesVizProps {
  widget: Widget;
  popover?: ReactNode;
  config: DashboardConfig;
  host?: WidgetHost;
}

const DashboardEntitiesViz = ({
  widget,
  popover,
  config,
  host,
}: DashboardEntitiesVizProps) => {
  const startDate = config.relativeDate
    ? computerRelativeDate(config.relativeDate)
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
        />
      );
    case 'number':
      return (
        <StixCoreObjectsNumber
          variant={undefined}
          height={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          entityType={undefined} // because calling js component in ts
          parameters={widget.parameters as object} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'list':
      return (
        <StixCoreObjectsList
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          widgetId={widget.id}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'distribution-list':
      return (
        <StixCoreObjectsDistributionList
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'vertical-bar':
      return (
        <StixCoreObjectsMultiVerticalBars
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'line':
      return (
        <StixCoreObjectsMultiLineChart
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'area':
      return (
        <StixCoreObjectsMultiAreaChart
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'timeline':
      return (
        <StixCoreObjectsTimeline
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'donut':
      return (
        <StixCoreObjectsDonut
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
    case 'polar-area':
      return (
        <StixCoreObjectsPolarArea
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters}
          popover={popover}
          host={host}
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
            endDate={endDate}
            startDate={startDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters as object} // because calling js component in ts
            height={undefined} // because calling js component in ts
            popover={popover}
            host={host}
          />
        );
      }
      return (
        <StixCoreObjectsHorizontalBars
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'radar':
      return (
        <StixCoreObjectsRadar
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'heatmap':
      return (
        <StixCoreObjectsMultiHeatMap
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'tree':
      return (
        <StixCoreObjectsTreeMap
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
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
