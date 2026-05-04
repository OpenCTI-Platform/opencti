import type { WidgetContext, WidgetDataSelection, WidgetPerspective } from '../../utils/widget/widget';
import { buildFiltersForCustomView, removeIdAndIncorrectKeysFromFilterGroupObject, useAvailableFilterKeysForEntityTypes } from '../../utils/filters/filtersUtils';

const useDashboardViz = ({
  dataSelection,
  perspective,
  context,
}: {
  dataSelection: WidgetDataSelection[];
  perspective: WidgetPerspective;
  context?: WidgetContext;
}) => {
  let mainEntityTypes = ['Stix-Core-Object'];
  if (perspective === 'relationships') {
    mainEntityTypes = ['stix-core-relationship', 'stix-sighting-relationship'];
  } else if (perspective === 'audits') {
    mainEntityTypes = ['History'];
  }
  const availableFilterKeysMain = useAvailableFilterKeysForEntityTypes(mainEntityTypes, true);
  const availableFilterKeysSecondary = useAvailableFilterKeysForEntityTypes(['Stix-Core-Object'], true);
  let contextEntityNeeded = false;
  const updatedDataSelection = dataSelection.map((data) => {
    let filters = [data.filters, data.dynamicFrom, data.dynamicTo];
    if (context?.kind === 'custom-view') {
      const resolvedFilters = filters.map((f) => buildFiltersForCustomView(f, context.customViewTargetEntityId));
      contextEntityNeeded = filters.some((f, i) => f !== resolvedFilters[i]);
      filters = resolvedFilters;
    }
    return {
      ...data,
      filters: removeIdAndIncorrectKeysFromFilterGroupObject(filters[0], availableFilterKeysMain),
      dynamicFrom: removeIdAndIncorrectKeysFromFilterGroupObject(filters[1], availableFilterKeysSecondary),
      dynamicTo: removeIdAndIncorrectKeysFromFilterGroupObject(filters[2], availableFilterKeysSecondary),
    };
  });
  const isPreviewMode = context?.kind === 'custom-view' && context.previewMode;
  const isMissingContextEntity = contextEntityNeeded && context?.kind === 'custom-view' && !context.customViewTargetEntityId;
  return {
    resolvedDataSelection: updatedDataSelection,
    isMissingContextEntity,
    isPreviewMode,
  };
};

export default useDashboardViz;
