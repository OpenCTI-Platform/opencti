import moment from 'moment';
import { getAvailableFilterKeysForEntityTypes, removeIdAndIncorrectKeysFromFilterGroupObject } from '../../filters/filtersUtils';
import type { Filter } from '../../filters/filtersHelpers-types';
import type { DrilldownBucket, FilterGroup, FilterKeysSchema, ListRouteResolution, WidgetDateRange } from './widgetDrilldown-types';

const INTERVAL_UNITS: Record<string, moment.unitOfTime.DurationConstructor> = {
  day: 'day',
  week: 'week',
  month: 'month',
  quarter: 'quarter',
  year: 'year',
};

/**
 * Recovers the Elasticsearch bucket start from the date returned by the API.
 *
 * `fillTimeSeries` computes period starts using the offset carried by the dates
 * the frontend sent, so the returned instant is the local period start expressed
 * in UTC. Its local calendar day *is* the bucket. Reinterpreting that day at UTC
 * midnight yields the true Elasticsearch boundary.
 */
const toUtcBucketStart = (bucketDate: string) => {
  const local = moment(bucketDate, moment.ISO_8601);
  if (!local.isValid()) return null;
  return moment.utc(local.format('YYYY-MM-DD'), 'YYYY-MM-DD', true);
};

/**
 * Builds the date filters reproducing exactly the documents counted by one
 * time-series bucket: `[bucketStart, bucketEnd[`, clamped by the widget's own
 * range, since Elasticsearch truncates the first and last buckets.
 */
export const buildBucketDateFilter = (
  bucketDate: string,
  interval: string,
  range: WidgetDateRange,
  dateAttribute: string,
): Filter[] | null => {
  const unit = INTERVAL_UNITS[interval];
  if (!unit) return null;

  const bucketStart = toUtcBucketStart(bucketDate);
  if (!bucketStart || !bucketStart.isValid()) return null;
  const bucketEnd = bucketStart.clone().add(1, unit);

  const rangeStart = range.startDate ? moment.utc(range.startDate) : null;
  const rangeEnd = range.endDate ? moment.utc(range.endDate) : null;

  const lowerBound = rangeStart?.isValid() && rangeStart.isAfter(bucketStart) ? rangeStart : bucketStart;
  const isUpperClamped = !!rangeEnd?.isValid() && rangeEnd.isBefore(bucketEnd);
  const upperBound = isUpperClamped ? rangeEnd! : bucketEnd;

  return [
    { key: dateAttribute, values: [lowerBound.toISOString()], operator: 'gte', mode: 'or' },
    { key: dateAttribute, values: [upperBound.toISOString()], operator: isUpperClamped ? 'lte' : 'lt', mode: 'or' },
  ];
};

type ValueSource = 'label' | 'entityId';

const ATTRIBUTE_TO_FILTER: Record<string, { key: string; source: ValueSource }> = {
  entity_type: { key: 'entity_type', source: 'label' },
  relationship_type: { key: 'relationship_type', source: 'label' },
  x_opencti_workflow_id: { key: 'x_opencti_workflow_id', source: 'label' },
  creator_id: { key: 'creator_id', source: 'entityId' },
  'created-by.internal_id': { key: 'createdBy', source: 'entityId' },
  'object-label.internal_id': { key: 'objectLabel', source: 'entityId' },
  'object-marking.internal_id': { key: 'objectMarking', source: 'entityId' },
  'object-assignee.internal_id': { key: 'objectAssignee', source: 'entityId' },
  'kill-chain-phase.internal_id': { key: 'killChainPhases', source: 'entityId' },
};

/**
 * Attributes a relationship distribution aggregates on the *connections* of each
 * relationship rather than on its own fields: `elAggregationRelationsCount`
 * switches to a nested aggregation for `internal_id` and `entity_type`
 * (engine.ts:3479-3493), so a bucket describes the entity sitting on one side,
 * not the relationship itself.
 *
 * Mapping them to `entity_type` would be plainly wrong -- a bucket labelled
 * `Malware` means "relationships whose endpoint is a malware", never
 * "relationships of type Malware".
 */
const CONNECTION_ATTRIBUTE_TO_FILTER: Record<string, { from: string; to: string; source: ValueSource }> = {
  internal_id: { from: 'fromId', to: 'toId', source: 'entityId' },
  entity_type: { from: 'fromTypes', to: 'toTypes', source: 'label' },
};

/**
 * Resolves which side of the relationship the displayed count came from.
 *
 * `buildAggregationFilter` (middleware-loader.ts:154-180) only adds a role
 * clause for a strictly boolean `isTo`: `false` pins `*_from`, `true` pins
 * `*_to`. Anything else leaves the aggregation counting both endpoints, which no
 * single-sided list filter reproduces.
 */
const connectionFilterKey = (attribute: string, isTo?: boolean | null) => {
  const sides = CONNECTION_ATTRIBUTE_TO_FILTER[attribute];
  if (!sides) return null;
  if (isTo !== true && isTo !== false) return null;
  return { key: isTo ? sides.to : sides.from, source: sides.source };
};

/** The part of the data selection the attribute mapping depends on. */
export interface BucketSelection {
  attribute: string;
  perspective: string;
  isTo?: boolean | null;
}

const resolveAttributeFilter = ({ attribute, perspective, isTo }: BucketSelection) => {
  if (perspective === 'relationships') {
    const connection = connectionFilterKey(attribute, isTo);
    if (connection) return connection;
    // `internal_id` has no meaning outside a connection aggregation.
    if (CONNECTION_ATTRIBUTE_TO_FILTER[attribute]) return null;
  }
  return ATTRIBUTE_TO_FILTER[attribute] ?? null;
};

/**
 * Bucket labels naming an entity or relationship type come back `pascalize`d
 * (`engine.ts:3402` and `:3530`), which mangles every type whose canonical
 * spelling is not pure Pascal case: `IPv4-Addr` is returned as `Ipv4-Addr`,
 * `StixFile` as `Stixfile`, `targets` as `Targets`. Such a value filters
 * nothing, so the list would open empty next to a non-zero widget.
 *
 * The filter keys schema is keyed by the canonical type names, which makes it
 * the reference to map a mangled label back.
 */
const TYPE_VALUED_FILTER_KEYS = ['entity_type', 'relationship_type', 'fromTypes', 'toTypes'];

export const canonicalEntityType = (value: string, schema: FilterKeysSchema): string => {
  if (schema.size === 0 || schema.has(value)) return value;
  const target = value.toLowerCase();
  for (const key of schema.keys()) {
    if (key.toLowerCase() === target) return key;
  }
  return value;
};

/** Filters the platform can express in a widget but a list page cannot reproduce. */
const NON_TRANSPOSABLE_KEYS = ['dynamicFrom', 'dynamicTo'];

/**
 * Elasticsearch groups documents missing the aggregated field under a bucket
 * literally keyed `unknown` (`terms.missing`, `engine.ts:3384`). Its count is
 * real but no filter value reproduces it, so the bucket must stay inert rather
 * than open a list of zero results. The rest of the frontend recognises the same
 * sentinel (`buildWidgetLabelsOption`, `useDistributionGraphData.ts`).
 *
 * Buckets whose referenced entity is restricted need no such guard: they resolve
 * to no `entityId` and are already rejected below.
 */
const MISSING_VALUE_BUCKET = 'unknown';

/**
 * Asks the very question the destination page will ask.
 *
 * Every list runs the incoming filters through
 * `removeIdAndIncorrectKeysFromFilterGroupObject` against the entity types *it*
 * pins, silently dropping anything unavailable there -- which would change the
 * count. So the support check must be scoped to the destination, never to the
 * widget: `entity_type` for instance is deleted from the schema of every
 * concrete type (`filterKeysSchema.ts:545`), yet the entities list, scoped to
 * the abstract `Stix-Domain-Object`, accepts it perfectly well.
 */
const isFilterKeySupported = (filterKey: string, scopeTypes: string[], schema: FilterKeysSchema) => {
  if (schema.size === 0) return true; // schema not loaded yet: do not block on an empty map
  const scopes = scopeTypes.length > 0 ? scopeTypes : [...schema.keys()];
  return getAvailableFilterKeysForEntityTypes(schema, scopes, true).includes(filterKey);
};

/**
 * Builds the filter isolating one distribution bucket.
 * Returns null whenever the bucket cannot be expressed as a list filter, which
 * makes the surface inert rather than opening a list with a different count.
 */
export const buildBucketValueFilter = (
  selection: BucketSelection,
  bucket: DrilldownBucket,
  destination: ListRouteResolution,
  filterKeysSchema: FilterKeysSchema,
): Filter[] | null => {
  if (bucket.kind !== 'distribution') return [];

  const mapping = resolveAttributeFilter(selection);
  if (!mapping) return null;

  if (bucket.rawValue === MISSING_VALUE_BUCKET) return null;

  const rawValue = mapping.source === 'entityId' ? bucket.entityId : bucket.rawValue;
  if (!rawValue) return null;
  const value = TYPE_VALUED_FILTER_KEYS.includes(mapping.key)
    ? canonicalEntityType(rawValue, filterKeysSchema)
    : rawValue;

  // A dedicated destination pins that very type on its own query, so the bucket
  // is already isolated. Keeping the filter would be redundant, and the page
  // would drop it anyway: `entity_type` is not a filter key of a concrete type.
  if (mapping.key === 'entity_type'
    && destination.consumedEntityType
    && value.toLowerCase() === destination.consumedEntityType.toLowerCase()) {
    return [];
  }

  if (!isFilterKeySupported(mapping.key, destination.scopeTypes, filterKeysSchema)) return null;

  return [{ key: mapping.key, values: [value], operator: 'eq', mode: 'or' }];
};

/**
 * Widget filters may reference sub-queries (`dynamicFrom` / `dynamicTo`) that no
 * list page can evaluate. Such a widget is never clickable.
 */
export const assertRepresentable = (filters?: FilterGroup | null): boolean => {
  if (!filters) return true;
  if (filters.filters.some((f) => NON_TRANSPOSABLE_KEYS.includes(f.key))) return false;
  return (filters.filterGroups ?? []).every((group) => assertRepresentable(group));
};

const countFilters = (group?: FilterGroup | null): number => (
  group ? group.filters.length + (group.filterGroups ?? []).reduce((acc, g) => acc + countFilters(g), 0) : 0
);

/**
 * Proves the destination list will honour every widget filter.
 *
 * A list page runs the incoming URL filters through
 * `removeIdAndIncorrectKeysFromFilterGroupObject` scoped to the types it pins,
 * and **silently drops** whatever it does not support. A dropped filter widens
 * the result set, so the list would show more than the widget counted. Rather
 * than guess which keys travel, the same cleaning is replayed here and the link
 * is refused as soon as it removes anything.
 */
export const areWidgetFiltersSupported = (
  filters: FilterGroup | null,
  scopeTypes: string[],
  schema: FilterKeysSchema,
): boolean => {
  if (!filters) return true;
  if (schema.size === 0) return true; // schema not loaded yet: do not block on an empty map
  const scopes = scopeTypes.length > 0 ? scopeTypes : [...schema.keys()];
  const available = getAvailableFilterKeysForEntityTypes(schema, scopes, true);
  const cleaned = removeIdAndIncorrectKeysFromFilterGroupObject(filters as Parameters<typeof removeIdAndIncorrectKeysFromFilterGroupObject>[0], available);
  return countFilters(filters) === countFilters(cleaned as FilterGroup | undefined);
};
