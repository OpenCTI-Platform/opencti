import React from 'react';
import WidgetText from '@components/workspaces/dashboards/WidgetText';
import type { PublicManifestConfig, PublicManifestWidget } from './PublicManifest';
import { computerRelativeDate, dayStartDate, formatDate } from '../../../utils/Time';
import PublicStixCoreObjectsNumber from './PublicStixCoreObjectsNumber';
import PublicStixCoreObjectsList from './PublicStixCoreObjectsList';
import PublicStixCoreObjectsDistributionList from './PublicStixCoreObjectsDistributionList';
import PublicStixCoreObjectsMultiVerticalBars from './PublicStixCoreObjectsMultiVerticalBars';
import PublicStixCoreObjectsMultiLineChart from './PublicStixCoreObjectsMultiLineChart';
import PublicStixCoreObjectsMultiAreaChart from './PublicStixCoreObjectsMultiAreaChart';
import PublicStixCoreObjectsTimeline from './PublicStixCoreObjectsTimeline';
import PublicStixCoreObjectsDonut from './PublicStixCoreObjectsDonut';
import PublicStixCoreObjectsRadar from './PublicStixCoreObjectsRadar';
import PublicStixCoreObjectsMultiHeatMap from './PublicStixCoreObjectsMultiHeatMap';
import PublicStixCoreObjectsTreeMap from './PublicStixCoreObjectsTreeMap';
import PublicStixCoreRelationshipsNumber from './PublicStixRelationshipsNumber';
import PublicStixRelationshipsList from './PublicStixRelationshipsList';
import PublicStixRelationshipsDistributionList from './PublicStixRelationshipsDistributionList';
import PublicStixRelationshipsMultiVerticalBars from './PublicStixRelationshipsMultiVerticalBars';
import PublicStixRelationshipsMultiLineChart from './PublicStixRelationshipsMultiLineChart';
import PublicStixRelationshipsMultiAreaChart from './PublicStixRelationshipsMultiAreaChart';
import PublicStixRelationshipsTimeline from './PublicStixRelationshipsTimeline';
import PublicStixRelationshipsDonut from './PublicStixRelationshipsDonut';
import PublicStixRelationshipsRadar from './PublicStixRelationshipsRadar';
import PublicStixRelationshipsMultiHeatMap from './PublicStixRelationshipsMultiHeatMap';
import PublicStixRelationshipsTreeMap from './PublicStixRelationshipsTreeMap';
import PublicStixRelationshipsMap from './PublicStixRelationshipsMap';
import PublicStixCoreObjectsHorizontalBars from './PublicStixCoreObjectsHorizontalBars';
import PublicStixRelationshipsHorizontalBars from './PublicStixRelationshipsHorizontalBars';
import PublicStixDomainObjectBookmarksList from './PublicStixDomainObjectBookmarksList';

const usePublicDashboardWidgets = (uriKey: string, config?: PublicManifestConfig) => {
  const startDate = config?.relativeDate ? computerRelativeDate(config.relativeDate) : config?.startDate;
  const endDate = config?.relativeDate ? formatDate(dayStartDate(null, false)) : config?.endDate;

  const entityWidget = (widget: PublicManifestWidget) => {
    switch (widget.type) {
      case 'bookmark':
        return (
          <PublicStixDomainObjectBookmarksList
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'number':
        return (
          <PublicStixCoreObjectsNumber
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'list':
        return (
          <PublicStixCoreObjectsList
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'distribution-list':
        return (
          <PublicStixCoreObjectsDistributionList
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'vertical-bar':
        return (
          <PublicStixCoreObjectsMultiVerticalBars
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'line':
        return (
          <PublicStixCoreObjectsMultiLineChart
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'area':
        return (
          <PublicStixCoreObjectsMultiAreaChart
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'timeline':
        return (
          <PublicStixCoreObjectsTimeline
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'donut':
        return (
          <PublicStixCoreObjectsDonut
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'horizontal-bar':
        if (false) {
          // TODO implement multi horizontal bars with breakdowns
          return 'Not implemented yet';
        }
        return (
          <PublicStixCoreObjectsHorizontalBars
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'radar':
        return (
          <PublicStixCoreObjectsRadar
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'heatmap':
        return (
          <PublicStixCoreObjectsMultiHeatMap
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'tree':
        return (
          <PublicStixCoreObjectsTreeMap
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      default:
        return 'Not implemented yet';
    }
  };

  const relationshipWidget = (widget: PublicManifestWidget) => {
    switch (widget.type) {
      case 'number':
        return (
          <PublicStixCoreRelationshipsNumber
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'list':
        return (
          <PublicStixRelationshipsList
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'distribution-list':
        return (
          <PublicStixRelationshipsDistributionList
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'vertical-bar':
        return (
          <PublicStixRelationshipsMultiVerticalBars
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'line':
        return (
          <PublicStixRelationshipsMultiLineChart
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'area':
        return (
          <PublicStixRelationshipsMultiAreaChart
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'timeline':
        return (
          <PublicStixRelationshipsTimeline
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'donut':
        return (
          <PublicStixRelationshipsDonut
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'horizontal-bar':
        if (false) {
          // TODO implement multi horizontal bars with breakdowns
          return 'Not implemented yet';
        }
        return (
          <PublicStixRelationshipsHorizontalBars
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'radar':
        return (
          <PublicStixRelationshipsRadar
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'heatmap':
        return (
          <PublicStixRelationshipsMultiHeatMap
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'tree':
        return (
          <PublicStixRelationshipsTreeMap
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      case 'map':
        return (
          <PublicStixRelationshipsMap
            startDate={startDate}
            endDate={endDate}
            uriKey={uriKey}
            widget={widget}
          />
        );
      default:
        return 'Not implemented yet';
    }
  };

  const rawWidget = (widget: PublicManifestWidget) => {
    switch (widget.type) {
      case 'text':
        return (
          <WidgetText
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      default:
        return 'Not implemented yet';
    }
  };

  return {
    entityWidget,
    relationshipWidget,
    rawWidget,
  };
};

export default usePublicDashboardWidgets;
