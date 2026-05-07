import { memo, ReactNode } from 'react';
import StixRelationshipsNumber from '@components/common/stix_relationships/StixRelationshipsNumber';
import StixRelationshipsList from '@components/common/stix_relationships/StixRelationshipsList';
import StixRelationshipsDistributionList from '@components/common/stix_relationships/StixRelationshipsDistributionList';
import StixRelationshipsMultiVerticalBars from '@components/common/stix_relationships/StixRelationshipsMultiVerticalBars';
import StixRelationshipsMultiLineChart from '@components/common/stix_relationships/StixRelationshipsMultiLineChart';
import StixRelationshipsMultiAreaChart from '@components/common/stix_relationships/StixRelationshipsMultiAreaChart';
import StixRelationshipsTimeline from '@components/common/stix_relationships/StixRelationshipsTimeline';
import StixRelationshipsDonut from '@components/common/stix_relationships/StixRelationshipsDonut';
import StixRelationshipsMultiHorizontalBars from '@components/common/stix_relationships/StixRelationshipsMultiHorizontalBars/StixRelationshipsMultiHorizontalBars';
import StixRelationshipsHorizontalBars from '@components/common/stix_relationships/StixRelationshipsHorizontalBars';
import StixRelationshipsRadar from '@components/common/stix_relationships/StixRelationshipsRadar';
import StixRelationshipsPolarArea from '@components/common/stix_relationships/StixRelationshipsPolarArea';
import StixRelationshipsMultiHeatMap from '@components/common/stix_relationships/StixRelationshipsMultiHeatMap';
import StixRelationshipsTreeMap from '@components/common/stix_relationships/StixRelationshipsTreeMap';
import StixRelationshipsMap from '@components/common/stix_relationships/StixRelationshipsMap';
import StixRelationshipsWordCloud from '@components/common/stix_relationships/StixRelationshipsWordCloud';
import { computerRelativeDate, dayStartDate, formatDate } from '../../utils/Time';
import type { Widget, WidgetHost } from '../../utils/widget/widget';
import type { DashboardConfig } from './dashboard-types';

interface DashboardRelationshipsVizProps {
  widget: Widget;
  popover?: ReactNode;
  config: DashboardConfig;
  host?: WidgetHost;
}

const DashboardRelationshipsViz = ({
  widget,
  popover,
  config,
  host,
}: DashboardRelationshipsVizProps) => {
  const startDate = config.relativeDate
    ? computerRelativeDate(config.relativeDate)
    : config.startDate;

  const endDate = config.relativeDate
    ? formatDate(dayStartDate(null, false))
    : config.endDate;

  switch (widget.type) {
    case 'number':
      return (
        <StixRelationshipsNumber
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
        <StixRelationshipsList
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          widgetId={widget.id}
          dataSelection={widget.dataSelection} // dynamicFrom and dynamicTo TODO
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'distribution-list':
      return (
        <StixRelationshipsDistributionList // TODO idem
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
          overflow={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'vertical-bar':
      return (
        <StixRelationshipsMultiVerticalBars
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
        <StixRelationshipsMultiLineChart
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
        <StixRelationshipsMultiAreaChart
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          relationshipTypes={undefined}
          popover={popover}
          host={host}
        />
      );
    case 'timeline':
      return (
        <StixRelationshipsTimeline
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
        <StixRelationshipsDonut
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'horizontal-bar':
      if (
        widget.dataSelection.length > 1
        && widget.dataSelection[0].attribute === 'internal_id'
      ) {
        return (
          <StixRelationshipsMultiHorizontalBars
            variant={undefined}
            endDate={endDate}
            startDate={startDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters as object} // because calling js component in ts
            height={undefined} // because calling js component in ts
            title={undefined} // because calling js component in ts
            field={undefined} // because calling js component in ts
            popover={popover}
            host={host}
          />
        );
      }
      return (
        <StixRelationshipsHorizontalBars
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
          fromId={undefined} // because calling js component in ts
          relationshipType={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'radar':
      return (
        <StixRelationshipsRadar
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'polar-area':
      return (
        <StixRelationshipsPolarArea
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'heatmap':
      return (
        <StixRelationshipsMultiHeatMap
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
        <StixRelationshipsTreeMap
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'map':
      return (
        <StixRelationshipsMap
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    case 'wordcloud':
      return (
        <StixRelationshipsWordCloud
          variant={undefined}
          endDate={endDate}
          startDate={startDate}
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          title={undefined} // because calling js component in ts
          field={undefined} // because calling js component in ts
          popover={popover}
          host={host}
        />
      );
    default:
      return 'Not implemented yet';
  }
};

export default memo(DashboardRelationshipsViz);
