import { v4 as uuid } from 'uuid';
import { buildFiltersAndOptionsForWidgets, isFilterGroupNotEmpty } from '../../filters/filtersUtils';
import { assertRepresentable, buildBucketDateFilter, buildBucketValueFilter } from './widgetDrilldownFilters';
import { resolveListRoute } from './widgetDrilldownRoutes';
import type { DrilldownInput, FilterGroup } from './widgetDrilldown-types';
import type { Filter } from '../../filters/filtersHelpers-types';

const withUrlIds = (group: FilterGroup): FilterGroup => ({
  ...group,
  filters: group.filters.map((f) => ({ ...f, id: uuid() })),
  filterGroups: (group.filterGroups ?? []).map(withUrlIds),
});

const toFiltersUrl = (route: string, group: FilterGroup) => (
  `${route}?filters=${encodeURIComponent(JSON.stringify(withUrlIds(group)))}`
);

/**
 * Restricts the widget filters with the bucket bounds.
 *
 * The bucket filters are never appended to the widget group itself: that group
 * carries a user-chosen mode, and appending to an `or` group would widen the
 * result set instead of narrowing it. Nesting under a fresh `and` group is the
 * same shape `buildFiltersAndOptionsForWidgets` uses for its own date bounds.
 */
const restrictWith = (base: FilterGroup | undefined, bucketFilters: Filter[]): FilterGroup => ({
  mode: 'and',
  filters: bucketFilters,
  filterGroups: base && isFilterGroupNotEmpty(base) ? [base] : [],
});

/**
 * The relationships list page only holds stix-core-relationships: it pins that
 * type on every query (`Relationships.tsx:281`). A relationship widget, on the
 * other hand, aggregates over `stix-relationship` unless told otherwise
 * (`stixRelationship.js:36-38`) -- sightings and refs included, which is how
 * "Most active labels" counts `object-label` refs.
 *
 * So the widget must prove its own population is covered before a link can
 * promise the same count. Anything the platform cannot vouch for is refused.
 */
const isWithinCoreRelationships = (filters: FilterGroup | null, coreTypes: string[]): boolean => {
  if (!filters) return false;
  const covered = new Set(['stix-core-relationship', ...coreTypes].map((t) => t.toLowerCase()));
  const scoping = filters.filters.filter((f) => f.key === 'entity_type' || f.key === 'relationship_type');
  if (scoping.length === 0) return false;
  // Under `or`, a scoping filter no longer narrows the population: anything
  // matching a sibling filter is counted too, whatever its relationship type.
  if (filters.mode !== 'and' && filters.filters.length > 1) return false;
  return scoping.some((f) => (f.operator ?? 'eq') === 'eq'
    && f.values.length > 0
    && f.values.every((v) => typeof v === 'string' && covered.has(v.toLowerCase())));
};

/**
 * Turns a clicked widget surface into a link to a list reproducing exactly the
 * displayed number, or null when exactness cannot be guaranteed.
 */
export const resolveDrilldownLink = (input: DrilldownInput): string | null => {
  const { perspective, dataSelection, range, interval, bucket, filterKeysSchema, stixCoreRelationshipTypes } = input;

  const widgetFilters = (dataSelection.filters ?? null) as FilterGroup | null;
  if (!assertRepresentable(widgetFilters)) return null;

  if (perspective === 'relationships' && !isWithinCoreRelationships(widgetFilters, stixCoreRelationshipTypes)) {
    return null;
  }

  // A "distinct" audit selection counts values of a field, not documents:
  // `auditsNumber` switches to `elCardinalityCount` (log.ts:68) and the same
  // applies to its time series. A list page counts documents, and above
  // UNIQUE_COUNT_ESTIMATION_THRESHOLD the cardinality is not even exact.
  if (dataSelection.unique) return null;

  const destination = resolveListRoute(perspective, widgetFilters);
  if (!destination) return null;

  const dateAttribute = dataSelection.date_attribute || 'created_at';

  let bucketFilters: Filter[] | null;
  if (bucket.kind === 'timeSeries') {
    if (!interval) return null;
    bucketFilters = buildBucketDateFilter(bucket.date, interval, range, dateAttribute);
  } else {
    bucketFilters = buildBucketValueFilter(
      { attribute: dataSelection.attribute ?? '', perspective, isTo: dataSelection.isTo },
      bucket,
      (widgetFilters?.filters.find((f) => f.key === 'entity_type')?.values as string[]) ?? [],
      filterKeysSchema,
    );
  }
  if (bucketFilters === null) return null;

  // A dedicated destination already restricts to that type, so the filter would
  // be redundant in the URL. It is dropped before the group gets nested, since
  // afterwards it would no longer sit at the top level.
  const scopedFilters = destination.consumedEntityType && widgetFilters
    ? { ...widgetFilters, filters: widgetFilters.filters.filter((f) => f.key !== 'entity_type') }
    : widgetFilters;

  // A time-series bucket already carries its own bounds, clamped to the widget
  // range, so applying that range again would duplicate it. A `total` bucket has
  // no upper bound at all: `stixCoreObjectsNumber` drops `endDate` before
  // counting (stixCoreObject.js:465).
  const appliedRange = {
    startDate: bucket.kind === 'timeSeries' ? null : range.startDate,
    endDate: bucket.kind === 'timeSeries' || bucket.kind === 'total' ? null : range.endDate,
  };

  const { filters: base } = buildFiltersAndOptionsForWidgets(scopedFilters, {
    removeTypeAll: true,
    startDate: appliedRange.startDate,
    endDate: appliedRange.endDate,
    dateAttribute,
  });

  return toFiltersUrl(destination.route, restrictWith(base, bucketFilters));
};
