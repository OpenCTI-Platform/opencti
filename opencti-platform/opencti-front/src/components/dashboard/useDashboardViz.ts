import type { WidgetHost, WidgetDataSelection, WidgetPerspective } from '../../utils/widget/widget';
import { buildFiltersForCustomView, removeIdAndIncorrectKeysFromFilterGroupObject, useAvailableFilterKeysForEntityTypes } from '../../utils/filters/filtersUtils';

const useDashboardViz = ({
  dataSelection,
  perspective,
  host,
}: {
  dataSelection: WidgetDataSelection[];
  perspective: WidgetPerspective;
  host?: WidgetHost;
}) => {
  let mainEntityTypes = ['Stix-Core-Object'];
  if (perspective === 'relationships') {
    mainEntityTypes = ['stix-core-relationship', 'stix-sighting-relationship'];
  } else if (perspective === 'audits') {
    mainEntityTypes = ['History'];
  }
  const availableFilterKeysMain = useAvailableFilterKeysForEntityTypes(mainEntityTypes, true);
  const availableFilterKeysSecondary = useAvailableFilterKeysForEntityTypes(['Stix-Core-Object'], true);
  let hostEntityNeeded = false;
  const updatedDataSelection = dataSelection.map((data) => {
    let filters = [data.filters, data.dynamicFrom, data.dynamicTo];
    if (host?.kind === 'custom-view') {
      const resolvedFilters = filters.map((f) => buildFiltersForCustomView(f, host.customViewTargetEntityId));
      hostEntityNeeded = hostEntityNeeded || filters.some((f, i) => f !== resolvedFilters[i]);
      filters = resolvedFilters;
    }
    return {
      ...data,
      filters: removeIdAndIncorrectKeysFromFilterGroupObject(filters[0], availableFilterKeysMain),
      dynamicFrom: removeIdAndIncorrectKeysFromFilterGroupObject(filters[1], availableFilterKeysSecondary),
      dynamicTo: removeIdAndIncorrectKeysFromFilterGroupObject(filters[2], availableFilterKeysSecondary),
    };
  });
  const isPreviewMode = host?.kind === 'custom-view' && host.previewMode;
  const isMissingHostEntity = hostEntityNeeded && host?.kind === 'custom-view' && !host.customViewTargetEntityId;
  return {
    resolvedDataSelection: updatedDataSelection,
    isMissingHostEntity,
    isPreviewMode,
  };
};

export default useDashboardViz;
