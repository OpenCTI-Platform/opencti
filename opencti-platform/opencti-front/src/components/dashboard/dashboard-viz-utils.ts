import type { WidgetHost, WidgetDataSelection, WidgetPerspective } from 'src/utils/widget/widget';
import { buildFiltersForCustomView, removeIdAndIncorrectKeysFromFilterGroupObject, getAvailableFilterKeysForEntityTypes } from 'src/utils/filters/filtersUtils';
import { type FilterDefinition } from 'src/utils/hooks/useAuth';
import { computeRelativeDate, dayStartDate, formatDate } from 'src/utils/Time';
import type { FilterGroup } from 'src/utils/filters/filtersHelpers-types';
import { DashboardConfig } from './dashboard-types';

const VAR_SENTINEL_PREFIX = '__var__:';

const substituteSentinelInValue = (value: unknown, variableValues: Record<string, string>): unknown => {
  if (typeof value === 'string' && value.startsWith(VAR_SENTINEL_PREFIX)) {
    const variableId = value.slice(VAR_SENTINEL_PREFIX.length);
    const resolved = variableValues[variableId];
    return resolved !== undefined ? resolved : undefined;
  }
  if (Array.isArray(value)) {
    const nextArray = value
      .map((v) => substituteSentinelInValue(v, variableValues))
      .filter((v): v is NonNullable<typeof v> => v !== undefined);
    return nextArray;
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => [k, substituteSentinelInValue(v, variableValues)] as const)
      .filter(([, v]) => v !== undefined);
    const nextObject = Object.fromEntries(entries);
    if ('values' in nextObject && Array.isArray(nextObject.values) && nextObject.values.length === 0) {
      return undefined;
    }
    return Object.keys(nextObject).length > 0 ? nextObject : undefined;
  }
  return value;
};

/** Replace `__var__:{id}` sentinel values in a FilterGroup with actual variable values. */
const substituteVariableSentinels = (
  filterGroup: FilterGroup | null | undefined,
  variableValues: Record<string, string>,
): FilterGroup | null | undefined => {
  if (!filterGroup) return filterGroup;
  return {
    ...filterGroup,
    filters: (filterGroup.filters ?? []).map((filter) => {
      if (!filter.values || filter.values.length === 0) return filter;
      const substituted = filter.values
        .map((v) => substituteSentinelInValue(v, variableValues))
        .filter((v): v is NonNullable<typeof v> => v !== undefined);
      return { ...filter, values: substituted };
    }).filter((filter) => {
      const operator = filter.operator ?? 'eq';
      if (['nil', 'not_nil', 'has_changed', 'not_has_changed'].includes(operator)) {
        return true;
      }
      return (filter.values?.length ?? 0) > 0;
    }),
    filterGroups: (filterGroup.filterGroups ?? []).map((fg) => substituteVariableSentinels(fg, variableValues) as FilterGroup),
  };
};

export const resolveDataSelection = ({
  filterKeysSchema,
  dataSelection,
  perspective,
  host,
  variableValues = {},
}: {
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>;
  dataSelection: WidgetDataSelection[];
  perspective: WidgetPerspective;
  host?: WidgetHost;
  variableValues?: Record<string, string>;
}) => {
  let mainEntityTypes = ['Stix-Core-Object', 'DraftWorkspace'];
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
    // Always run substitution to remove unresolved sentinel values safely.
    filters = filters.map((f) => substituteVariableSentinels(f, variableValues));
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
  const isMissingHostEntity = host?.kind === 'custom-view'
    && hostEntityNeeded
    && !host.customViewTargetEntityId;
  const isPreviewMode = host?.kind === 'custom-view' && hostEntityNeeded && Boolean(host.customViewTargetEntityId) && host.previewMode;
  return {
    resolvedDataSelection: updatedDataSelection,
    isMissingHostEntity,
    isPreviewMode,
  };
};

export const computeStartEndDates = (config?: DashboardConfig) => {
  const startDate = config?.relativeDate
    ? computeRelativeDate(config.relativeDate)
    : config?.startDate;

  const endDate = config?.relativeDate
    ? formatDate(dayStartDate(null, false))
    : config?.endDate;

  return { startDate, endDate };
};
