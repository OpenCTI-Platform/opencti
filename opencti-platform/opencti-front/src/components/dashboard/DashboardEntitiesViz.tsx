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
import StixCoreObjectsWordCloud from '../../private/components/common/stix_core_objects/StixCoreObjectsWordCloud';
import DraftsNumber from '@components/common/drafts/DraftsNumber';
import DraftsList from '@components/common/drafts/DraftsList';
import DraftsDistributionList from '@components/common/drafts/DraftsDistributionList';
import DraftsDonut from '@components/common/drafts/DraftsDonut';
import DraftsHorizontalBars from '@components/common/drafts/DraftsHorizontalBars';
import DraftsMultiVerticalBars from '@components/common/drafts/DraftsMultiVerticalBars';
import DraftsMultiLineChart from '@components/common/drafts/DraftsMultiLineChart';
import DraftsMultiAreaChart from '@components/common/drafts/DraftsMultiAreaChart';
import type { Widget, WidgetHost } from '../../utils/widget/widget';
import type { DashboardConfig } from './dashboard-types';
import { isDraftWorkspaceFilterGroup } from '../../utils/filters/filtersUtils';
import WidgetNotImplemented from './WidgetNotImplemented';

interface DashboardEntitiesVizProps {
  widget: Widget;
  popover?: ReactNode;
  config: DashboardConfig;
  host?: WidgetHost;
  refreshRate?: number | null;
}

const isDraftWorkspaceWidget = (widgetData: Widget): boolean => {
  return widgetData.dataSelection.length > 0
    && widgetData.dataSelection.every((selection) => isDraftWorkspaceFilterGroup(selection.filters));
};

const DashboardEntitiesViz = ({
  widget,
  popover,
  config,
  host,
  refreshRate,
}: DashboardEntitiesVizProps) => {
  const isDraftWidget = isDraftWorkspaceWidget(widget);

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
      if (isDraftWidget) {
        return (
          <DraftsNumber
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
      }
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
      if (isDraftWidget) {
        return (
          <DraftsList
            variant={undefined} // because calling js component in ts
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
      }
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
      if (isDraftWidget) {
        return (
          <DraftsDistributionList
            variant={undefined} // because calling js component in ts
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
      if (isDraftWidget) {
        return (
          <DraftsMultiVerticalBars
            variant={undefined} // because calling js component in ts
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
      if (isDraftWidget) {
        return (
          <DraftsMultiLineChart
            variant={undefined} // because calling js component in ts
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
      if (isDraftWidget) {
        return (
          <DraftsMultiAreaChart
            variant={undefined} // because calling js component in ts
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
      if (isDraftWidget) {
        return (
          <DraftsDonut
            variant={undefined} // because calling js component in ts
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
      if (isDraftWidget) {
        return (
          <DraftsHorizontalBars
            variant={undefined} // because calling js component in ts
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
          dataSelection={widget.dataSelection}
          parameters={widget.parameters as object} // because calling js component in ts
          height={undefined}
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

export default memo(DashboardEntitiesViz);
