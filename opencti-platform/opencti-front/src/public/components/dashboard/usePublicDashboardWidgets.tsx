import React from 'react';
import WidgetText from '@components/workspaces/dashboards/WidgetText';
import type { PublicManifestConfig, PublicManifestWidget } from './PublicManifest';
import { computerRelativeDate, dayStartDate, formatDate } from '../../../utils/Time';
import PublicStixCoreObjectsNumber from './stix_core_objects/PublicStixCoreObjectsNumber';
import PublicStixCoreObjectsList from './stix_core_objects/PublicStixCoreObjectsList';
import PublicStixCoreObjectsDistributionList from './stix_core_objects/PublicStixCoreObjectsDistributionList';
import PublicStixCoreObjectsMultiVerticalBars from './stix_core_objects/PublicStixCoreObjectsMultiVerticalBars';
import PublicStixCoreObjectsMultiLineChart from './stix_core_objects/PublicStixCoreObjectsMultiLineChart';
import PublicStixCoreObjectsMultiAreaChart from './stix_core_objects/PublicStixCoreObjectsMultiAreaChart';
import PublicStixCoreObjectsTimeline from './stix_core_objects/PublicStixCoreObjectsTimeline';
import PublicStixCoreObjectsDonut from './stix_core_objects/PublicStixCoreObjectsDonut';
import PublicStixCoreObjectsRadar from './stix_core_objects/PublicStixCoreObjectsRadar';
import PublicStixCoreObjectsMultiHeatMap from './stix_core_objects/PublicStixCoreObjectsMultiHeatMap';
import PublicStixCoreObjectsTreeMap from './stix_core_objects/PublicStixCoreObjectsTreeMap';
import PublicStixCoreRelationshipsNumber from './stix_relationships/PublicStixRelationshipsNumber';
import PublicStixRelationshipsList from './stix_relationships/PublicStixRelationshipsList';
import PublicStixRelationshipsDistributionList from './stix_relationships/PublicStixRelationshipsDistributionList';
import PublicStixRelationshipsMultiVerticalBars from './stix_relationships/PublicStixRelationshipsMultiVerticalBars';
import PublicStixRelationshipsMultiLineChart from './stix_relationships/PublicStixRelationshipsMultiLineChart';
import PublicStixRelationshipsMultiAreaChart from './stix_relationships/PublicStixRelationshipsMultiAreaChart';
import PublicStixRelationshipsTimeline from './stix_relationships/PublicStixRelationshipsTimeline';
import PublicStixRelationshipsDonut from './stix_relationships/PublicStixRelationshipsDonut';
import PublicStixRelationshipsRadar from './stix_relationships/PublicStixRelationshipsRadar';
import PublicStixRelationshipsMultiHeatMap from './stix_relationships/PublicStixRelationshipsMultiHeatMap';
import PublicStixRelationshipsTreeMap from './stix_relationships/PublicStixRelationshipsTreeMap';
import PublicStixRelationshipsMap from './stix_relationships/PublicStixRelationshipsMap';
import PublicStixCoreObjectsHorizontalBars from './stix_core_objects/PublicStixCoreObjectsHorizontalBars';
import PublicStixRelationshipsHorizontalBars from './stix_relationships/PublicStixRelationshipsHorizontalBars';
import PublicStixRelationshipsMultiHorizontalBars from './stix_relationships/PublicStixRelationshipsMultiHorizontalBars';
import PublicStixRelationshipsPolarArea from './stix_relationships/PublicStixRelationshipsPolarArea';
import PublicStixCoreObjectsPolarArea from './stix_core_objects/PublicStixCoreObjectsPolarArea';
import { useFormatter } from '../../../components/i18n';

const usePublicDashboardWidgets = (uriKey: string, config?: PublicManifestConfig) => {
  const { t_i18n } = useFormatter();

  const startDate = config?.relativeDate ? computerRelativeDate(config.relativeDate) : config?.startDate;
  const endDate = config?.relativeDate ? formatDate(dayStartDate(null, false)) : config?.endDate;

  const entityWidget = (widget: PublicManifestWidget) => {
    switch (widget.type) {
      case 'bookmark':
        return t_i18n('Bookmarks are not supported in public dashboards');
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
        if (widget.dataSelection.length > 1) {
          // TODO implement multi horizontal bars with breakdowns
          return t_i18n('Not implemented yet');
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
      case 'polar-area':
        return (
          <PublicStixCoreObjectsPolarArea
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
        return t_i18n('Not implemented yet');
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
        if (widget.dataSelection.length > 1) {
          return (
            <PublicStixRelationshipsMultiHorizontalBars
              startDate={startDate}
              endDate={endDate}
              uriKey={uriKey}
              widget={widget}
            />
          );
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
      case 'polar-area':
        return (
          <PublicStixRelationshipsPolarArea
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
        return t_i18n('Not implemented yet');
    }
  };

  const auditWidget = (widget: PublicManifestWidget) => {
    switch (widget.type) {
      default:
        return t_i18n('Audits are not supported in public dashboards');
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
        return t_i18n('Not implemented yet');
    }
  };

  return {
    entityWidget,
    relationshipWidget,
    auditWidget,
    rawWidget,
  };
};

export default usePublicDashboardWidgets;
