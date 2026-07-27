import { memo, ReactNode } from 'react';
import StixRelationshipsNumber from '../../private/components/common/stix_relationships/StixRelationshipsNumber';
import StixRelationshipsList from '../../private/components/common/stix_relationships/StixRelationshipsList';
import StixRelationshipsDistributionList from '../../private/components/common/stix_relationships/StixRelationshipsDistributionList';
import StixRelationshipsMultiVerticalBars from '../../private/components/common/stix_relationships/StixRelationshipsMultiVerticalBars';
import StixRelationshipsMultiLineChart from '../../private/components/common/stix_relationships/StixRelationshipsMultiLineChart';
import StixRelationshipsMultiAreaChart from '../../private/components/common/stix_relationships/StixRelationshipsMultiAreaChart';
import StixRelationshipsTimeline from '@components/common/stix_relationships/StixRelationshipsTimeline';
import StixRelationshipsDonut from '@components/common/stix_relationships/StixRelationshipsDonut';
import StixRelationshipsMultiHorizontalBars from '@components/common/stix_relationships/StixRelationshipsMultiHorizontalBars/StixRelationshipsMultiHorizontalBars';
import StixRelationshipsHorizontalBars from '../../private/components/common/stix_relationships/StixRelationshipsHorizontalBars';
import StixRelationshipsRadar from '../../private/components/common/stix_relationships/StixRelationshipsRadar';
import StixRelationshipsPolarArea from '../../private/components/common/stix_relationships/StixRelationshipsPolarArea';
import StixRelationshipsMultiHeatMap from '../../private/components/common/stix_relationships/StixRelationshipsMultiHeatMap';
import StixRelationshipsTreeMap from '../../private/components/common/stix_relationships/StixRelationshipsTreeMap';
import StixRelationshipsMap from '../../private/components/common/stix_relationships/StixRelationshipsMap';
import StixRelationshipsWordCloud from '../../private/components/common/stix_relationships/StixRelationshipsWordCloud';
import type { Widget, WidgetHost } from '../../utils/widget/widget';
import type { DashboardConfig } from './dashboard-types';
import WidgetNotImplemented from './WidgetNotImplemented';

interface DashboardRelationshipsVizProps {
  widget: Widget;
  popover?: ReactNode;
  config: DashboardConfig;
  host?: WidgetHost;
  refreshRate?: number | null;
}

const DashboardRelationshipsViz = ({
  widget,
  popover,
  config,
  host,
  refreshRate,
}: DashboardRelationshipsVizProps) => {
  switch (widget.type) {
    case 'number':
      return (
        <StixRelationshipsNumber
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
        <StixRelationshipsList
          variant={undefined}
          widgetId={widget.id}
          dataSelection={widget.dataSelection} // dynamicFrom and dynamicTo TODO
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined} // because calling js component in ts
          popover={popover}
          host={host}
          refreshRate={refreshRate}
          config={config}
        />
      );
    case 'distribution-list':
      return (
        <StixRelationshipsDistributionList // TODO idem
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
        <StixRelationshipsMultiVerticalBars
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
        <StixRelationshipsMultiLineChart
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
        <StixRelationshipsMultiAreaChart
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
        <StixRelationshipsTimeline
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
        <StixRelationshipsDonut
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
    case 'horizontal-bar':
      if (
        widget.dataSelection.length > 1
        && widget.dataSelection[0].attribute === 'internal_id'
      ) {
        return (
          <StixRelationshipsMultiHorizontalBars
            variant={undefined}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters as object} // because calling js component in ts
            height={undefined} // because calling js component in ts
            title={undefined} // because calling js component in ts
            field={undefined} // because calling js component in ts
            popover={popover}
            host={host}
            refreshRate={refreshRate}
            config={config}
          />
        );
      }
      return (
        <StixRelationshipsHorizontalBars
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
        <StixRelationshipsRadar
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
    case 'polar-area':
      return (
        <StixRelationshipsPolarArea
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
        <StixRelationshipsMultiHeatMap
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
        <StixRelationshipsTreeMap
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
    case 'map':
      return (
        <StixRelationshipsMap
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
        <StixRelationshipsWordCloud
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
    default:
      return (
        <WidgetNotImplemented popover={popover} />
      );
  }
};

export default memo(DashboardRelationshipsViz);
