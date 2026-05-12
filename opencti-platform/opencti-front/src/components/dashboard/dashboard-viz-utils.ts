import type { WidgetHost, WidgetDataSelection, WidgetPerspective } from '../../utils/widget/widget';
import { buildFiltersForCustomView, removeIdAndIncorrectKeysFromFilterGroupObject, getAvailableFilterKeysForEntityTypes } from '../../utils/filters/filtersUtils';
import { type FilterDefinition } from '../../utils/hooks/useAuth';

export const resolveDataSelection = ({
  filterKeysSchema,
  dataSelection,
  perspective,
  host,
}: {
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>;
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
  const availableFilterKeysMain = getAvailableFilterKeysForEntityTypes(filterKeysSchema, mainEntityTypes, true);
  const availableFilterKeysSecondary = getAvailableFilterKeysForEntityTypes(filterKeysSchema, ['Stix-Core-Object'], true);
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
  const isMissingHostEntity = host?.kind === 'custom-view' && hostEntityNeeded && !host.customViewTargetEntityId;
  const isPreviewMode = host?.kind === 'custom-view' && hostEntityNeeded && Boolean(host.customViewTargetEntityId) && host.previewMode;
  return {
    resolvedDataSelection: updatedDataSelection,
    isMissingHostEntity,
    isPreviewMode,
  };
};
