import React from 'react';
import type { PublicManifestConfig, PublicManifestWidget } from './PublicManifest';
import { computerRelativeDate, dayStartDate, formatDate } from '../../../utils/Time';
import PublicStixCoreObjectsNumber from './PublicStixCoreObjectsNumber';

const usePublicDashboardWidgets = (uriKey: string, config: PublicManifestConfig) => {
  const startDate = config.relativeDate ? computerRelativeDate(config.relativeDate) : config.startDate;
  const endDate = config.relativeDate ? formatDate(dayStartDate(null, false)) : config.endDate;

  const entityWidget = (widget: PublicManifestWidget) => {
    switch (widget.type) {
      case 'bookmark':
        return 'Not implemented yet';
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
        return 'Not implemented yet';
      case 'distribution-list':
        return 'Not implemented yet';
      case 'vertical-bar':
        return 'Not implemented yet';
      case 'line':
        return 'Not implemented yet';
      case 'area':
        return 'Not implemented yet';
      case 'timeline':
        return 'Not implemented yet';
      case 'donut':
        return 'Not implemented yet';
      case 'horizontal-bar':
        return 'Not implemented yet';
      case 'radar':
        return 'Not implemented yet';
      case 'heatmap':
        return 'Not implemented yet';
      case 'tree':
        return 'Not implemented yet';
      default:
        return 'Not implemented yet';
    }
  };

  const relationshipWidget = (widget: PublicManifestWidget) => {
    switch (widget.type) {
      case 'number':
        return 'Not implemented yet';
      case 'list':
        return 'Not implemented yet';
      case 'distribution-list':
        return 'Not implemented yet';
      case 'vertical-bar':
        return 'Not implemented yet';
      case 'line':
        return 'Not implemented yet';
      case 'area':
        return 'Not implemented yet';
      case 'timeline':
        return 'Not implemented yet';
      case 'donut':
        return 'Not implemented yet';
      case 'horizontal-bar':
        return 'Not implemented yet';
      case 'radar':
        return 'Not implemented yet';
      case 'heatmap':
        return 'Not implemented yet';
      case 'tree':
        return 'Not implemented yet';
      case 'map':
        return 'Not implemented yet';
      default:
        return 'Not implemented yet';
    }
  };

  const rawWidget = (widget: PublicManifestWidget) => {
    switch (widget.type) {
      case 'text':
        return 'Not implemented yet';
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
