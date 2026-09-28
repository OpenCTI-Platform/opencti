import { v4 as uuid } from 'uuid';
import { buildFiltersAndOptionsForWidgets, isFilterGroupNotEmpty } from '../../filters/filtersUtils';
import { areWidgetFiltersSupported, assertRepresentable, buildBucketDateFilter, buildBucketValueFilter, canonicalEntityType } from './widgetDrilldownFilters';
import { resolveListRoute } from './widgetDrilldownRoutes';
import type { DrilldownInput, FilterGroup } from './widgetDrilldown-types';
import type { Filter } from '../../filters/filtersHelpers-types';

/**
 * A data selection can carry sub-queries restricting the source or the target of
 * the counted relationships. They are separate GraphQL variables, not filters,
 * and a list URL has nowhere to put them.
 */
const hasDynamicSubQuery = (dataSelection: DrilldownInput['dataSelection']): boolean => (
  isFilterGroupNotEmpty(dataSelection.dynamicFrom as FilterGroup | null | undefined)
  || isFilterGroupNotEmpty(dataSelection.dynamicTo as FilterGroup | null | undefined)
  || !!dataSelection.dynamicFrom_id
  || !!dataSelection.dynamicTo_id
);

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
 * Generic list pages hold strictly less than their widgets count: the entities
 * list queries `stixDomainObjects` (`Entities.tsx:45`) while an entity widget
 * aggregates every `Stix-Core-Object`, and the relationships list pins
 * `stix-core-relationship` (`Relationships.tsx:281`) while a relationship widget
 * aggregates over `stix-relationship` (`stixRelationship.js:36-38`) -- sightings
 * and refs included, which is how "Most active labels" counts `object-label`
 * refs.
 *
 * So the counted population must be proven covered before a link can promise the
 * same number. Anything the widget cannot vouch for is refused.
 */
const isWithinDestinationScope = (
  filters: FilterGroup | null,
  bucketEntityType: string | null,
  scopeTypes: string[],
  subtypesByAbstractType: Record<string, string[]>,
): boolean => {
  const covered = new Set(
    scopeTypes.flatMap((type) => [type, ...(subtypesByAbstractType[type] ?? [])]).map((t) => t.toLowerCase()),
  );
  const isCovered = (values: unknown[]) => values.length > 0
    && values.every((v) => typeof v === 'string' && covered.has(v.toLowerCase()));

  // A distribution on the type itself pins it exactly, whatever the widget
  // filters say: the bucket filter alone isolates a single entity type.
  if (bucketEntityType) return isCovered([bucketEntityType]);

  if (!filters) return false;
  const scoping = filters.filters.filter((f) => f.key === 'entity_type' || f.key === 'relationship_type');
  if (scoping.length === 0) return false;
  // Under `or`, a scoping filter no longer narrows the population: anything
  // matching a sibling filter -- or a sibling sub-group -- is counted too,
  // whatever its type.
  if (filters.mode !== 'and'
    && (filters.filters.length > 1 || (filters.filterGroups ?? []).length > 0)) return false;
  return scoping.some((f) => (f.operator ?? 'eq') === 'eq' && isCovered(f.values));
};

/**
 * Replaces the widget's own type restriction with the single type the bucket
 * isolates, so the destination can be the dedicated list of that type.
 */
const withEntityType = (filters: FilterGroup | null, entityType: string): FilterGroup => ({
  mode: 'and',
  filters: [
    ...(filters?.filters ?? []).filter((f) => f.key !== 'entity_type'),
    { key: 'entity_type', values: [entityType], operator: 'eq', mode: 'or' },
  ],
  filterGroups: filters?.filterGroups ?? [],
});

/**
 * Turns a clicked widget surface into a link to a list reproducing exactly the
 * displayed number, or null when exactness cannot be guaranteed.
 */
export const resolveDrilldownLink = (input: DrilldownInput): string | null => {
  const { perspective, dataSelection, range, configRange, interval, bucket, filterKeysSchema, subtypesByAbstractType } = input;

  const widgetFilters = (dataSelection.filters ?? null) as FilterGroup | null;
  if (!assertRepresentable(widgetFilters)) return null;

  // `dynamicFrom` / `dynamicTo` are not filters but sibling sub-queries of the
  // data selection, resolved server-side into the relationship source and target
  // (`addDynamicFromAndToToFilters`). They travel as their own GraphQL variables,
  // so `assertRepresentable` never sees them, and no list URL can carry them.
  if (hasDynamicSubQuery(dataSelection)) return null;

  // A "distinct" audit selection counts values of a field, not documents:
  // `auditsNumber` switches to `elCardinalityCount` (log.ts:68) and the same
  // applies to its time series. A list page counts documents, and above
  // UNIQUE_COUNT_ESTIMATION_THRESHOLD the cardinality is not even exact.
  if (dataSelection.unique) return null;

  // Outside the relationships perspective, where the aggregation runs on the
  // connections of each relationship, an `entity_type` bucket names the type of
  // the counted documents themselves.
  const bucketEntityType = perspective !== 'relationships'
    && dataSelection.attribute === 'entity_type'
    && bucket.kind === 'distribution'
    && typeof bucket.rawValue === 'string'
    && bucket.rawValue !== ''
    ? canonicalEntityType(bucket.rawValue, filterKeysSchema)
    : null;

  const destination = resolveListRoute(
    perspective,
    bucketEntityType ? withEntityType(widgetFilters, bucketEntityType) : widgetFilters,
  );
  if (!destination) return null;

  if (destination.requiresScopeProof
    && !isWithinDestinationScope(widgetFilters, bucketEntityType, destination.scopeTypes, subtypesByAbstractType)) {
    return null;
  }

  // Every widget filter has to survive the destination, not just the bucket one:
  // a key the list drops would silently widen the result set.
  if (!areWidgetFiltersSupported(widgetFilters, destination.scopeTypes, filterKeysSchema)) return null;

  const dateAttribute = dataSelection.date_attribute || 'created_at';

  let bucketFilters: Filter[] | null;
  if (bucket.kind === 'timeSeries') {
    if (!interval) return null;
    bucketFilters = buildBucketDateFilter(bucket.date, interval, range, dateAttribute);
  } else {
    bucketFilters = buildBucketValueFilter(
      { attribute: dataSelection.attribute ?? '', perspective, isTo: dataSelection.isTo },
      bucket,
      destination,
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

  // A time-series bucket already carries its own bounds, clamped to the sent
  // range, so applying a range again would duplicate it.
  //
  // Every other bucket was counted through the widget filters, into which
  // `computeWidgetFiltersForSelection` had baked the dashboard range -- hence
  // `configRange`, and not what the container happened to send as variables.
  // `total` is no exception: `stixCoreObjectsNumber` (stixCoreObject.js:465) and
  // `stixRelationshipsNumber` (stixRelationship.js:65) drop the `endDate`
  // *argument*, which carries the 24h variation window, never the dashboard
  // bound sitting in the filters.
  const appliedRange = bucket.kind === 'timeSeries'
    ? { startDate: null, endDate: null }
    : { startDate: configRange.startDate, endDate: configRange.endDate };

  const { filters: base } = buildFiltersAndOptionsForWidgets(scopedFilters, {
    removeTypeAll: true,
    startDate: appliedRange.startDate,
    endDate: appliedRange.endDate,
    dateAttribute,
  });

  return toFiltersUrl(destination.route, restrictWith(base, bucketFilters));
};
