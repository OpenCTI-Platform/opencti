import { buildDataRestrictions, elRawSearch } from '../../database/engine';
import { READ_INDEX_HISTORY, READ_INDEX_STIX_META_RELATIONSHIPS, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../database/utils';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { ENTITY_TYPE_HISTORY } from '../../schema/internalObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { DatabaseError } from '../../config/errors';
import type { AuthContext, AuthUser } from '../../types/user';

export interface SinceReferenceCounter {
  relationships: number;
  updates: number;
  containerObjects: number;
}

type ReferenceDates = Map<string, string>;

const minDate = (references: ReferenceDates) => [...references.values()].sort()[0];

const connectionClause = (id: string, role?: string) => ({
  nested: {
    path: 'connections',
    query: {
      bool: {
        must: [
          { term: { 'connections.internal_id.keyword': id } },
          ...(role ? [{ term: { 'connections.role.keyword': role } }] : []),
        ],
      },
    },
  },
});

const runFiltersAggregation = async (
  context: AuthContext,
  user: AuthUser,
  index: string | string[],
  type: string,
  must: any[],
  mustNot: any[],
  filters: Record<string, any>,
): Promise<Map<string, number>> => {
  const body = {
    size: 0,
    query: { bool: { must, must_not: mustNot } },
    aggs: { per_element: { filters: { filters } } },
  };
  const data = await elRawSearch(context, user, type, { index, body }).catch((err: unknown) => {
    throw DatabaseError('Time machine counters aggregation fail', { cause: err, type });
  });
  const buckets: Record<string, { doc_count: number }> = data.aggregations?.per_element?.buckets ?? {};
  const counts = new Map<string, number>();
  Object.entries(buckets).forEach(([key, bucket]) => counts.set(key, bucket.doc_count));
  return counts;
};

const RELATIONSHIP_TYPES_CLAUSE = {
  bool: {
    should: [
      { terms: { 'parent_types.keyword': [ABSTRACT_STIX_CORE_RELATIONSHIP] } },
      { terms: { 'entity_type.keyword': [STIX_SIGHTING_RELATIONSHIP] } },
    ],
    minimum_should_match: 1,
  },
};
// Upper bound of the relationship types of one element (core relationship types and sightings)
const MAX_RELATIONSHIP_TYPES = 100;

/**
 * Relationships of each element by relationship type, created up to `endDate` included: one aggregation for all the
 * elements, whatever their number of relationships. The history ranges start right after a date, so a relationship
 * created at `endDate` is counted here and not as a later creation.
 */
export const countRelationshipsByTypeForElements = async (
  context: AuthContext,
  user: AuthUser,
  ids: string[],
  endDate: string,
): Promise<Map<string, Map<string, number>>> => {
  const result = new Map<string, Map<string, number>>();
  if (ids.length === 0) return result;
  const restrictions = await buildDataRestrictions(context, user);
  const filters: Record<string, any> = {};
  ids.forEach((id) => {
    filters[id] = connectionClause(id);
  });
  const body = {
    size: 0,
    query: { bool: { must: [RELATIONSHIP_TYPES_CLAUSE, { range: { created_at: { lte: endDate } } }, ...restrictions.must], must_not: restrictions.must_not } },
    aggs: { per_element: { filters: { filters }, aggs: { per_type: { terms: { field: 'entity_type.keyword', size: MAX_RELATIONSHIP_TYPES } } } } },
  };
  const data = await elRawSearch(context, user, ABSTRACT_STIX_CORE_RELATIONSHIP, { index: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, body }).catch((err: unknown) => {
    throw DatabaseError('Time machine relationship counts aggregation fail', { cause: err });
  });
  const buckets: Record<string, { per_type?: { buckets?: Array<{ key: string; doc_count: number }> } }> = data.aggregations?.per_element?.buckets ?? {};
  ids.forEach((id) => {
    const counts = new Map<string, number>();
    (buckets[id]?.per_type?.buckets ?? []).forEach((bucket) => counts.set(bucket.key, bucket.doc_count));
    result.set(id, counts);
  });
  return result;
};

// Relationships created after the reference date, by someone else than the user
const countNewRelationships = async (context: AuthContext, user: AuthUser, references: ReferenceDates) => {
  const restrictions = await buildDataRestrictions(context, user);
  const filters: Record<string, any> = {};
  references.forEach((reference, id) => {
    filters[id] = { bool: { must: [connectionClause(id), { range: { created_at: { gt: reference } } }] } };
  });
  const must = [RELATIONSHIP_TYPES_CLAUSE, { range: { created_at: { gt: minDate(references) } } }, ...restrictions.must];
  const mustNot = [{ term: { 'creator_id.keyword': user.id } }, ...restrictions.must_not];
  return runFiltersAggregation(context, user, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, ABSTRACT_STIX_CORE_RELATIONSHIP, must, mustNot, filters);
};

// Updates (and merges) recorded in the history after the reference date, by someone else than the user
const countUpdates = async (context: AuthContext, user: AuthUser, references: ReferenceDates) => {
  const restrictions = await buildDataRestrictions(context, user, { historyFiltering: true });
  const filters: Record<string, any> = {};
  references.forEach((reference, id) => {
    filters[id] = { bool: { must: [{ term: { 'context_data.id.keyword': id } }, { range: { timestamp: { gt: reference } } }] } };
  });
  const must = [
    { terms: { 'entity_type.keyword': [ENTITY_TYPE_HISTORY] } },
    { terms: { 'event_scope.keyword': ['update', 'merge'] } },
    { range: { timestamp: { gt: minDate(references) } } },
    ...restrictions.must,
  ];
  const mustNot = [{ term: { 'user_id.keyword': user.id } }, ...restrictions.must_not];
  return runFiltersAggregation(context, user, READ_INDEX_HISTORY, ENTITY_TYPE_HISTORY, must, mustNot, filters);
};

// Objects added to containers after the reference date, by someone else than the user
const countNewContainerObjects = async (context: AuthContext, user: AuthUser, references: ReferenceDates) => {
  const restrictions = await buildDataRestrictions(context, user);
  const filters: Record<string, any> = {};
  references.forEach((reference, id) => {
    filters[id] = { bool: { must: [connectionClause(id, `${RELATION_OBJECT}_from`), { range: { created_at: { gt: reference } } }] } };
  });
  const must = [
    { terms: { 'entity_type.keyword': [RELATION_OBJECT] } },
    { range: { created_at: { gt: minDate(references) } } },
    ...restrictions.must,
  ];
  const mustNot = [{ term: { 'creator_id.keyword': user.id } }, ...restrictions.must_not];
  return runFiltersAggregation(context, user, READ_INDEX_STIX_META_RELATIONSHIPS, RELATION_OBJECT, must, mustNot, filters);
};

/**
 * Count, for each element, what changed after its reference date (last visit of the user):
 * new relationships, updates and objects added to containers. Three aggregation queries
 * whatever the number of elements, with the access restrictions of the user.
 */
export const countSinceReferenceDates = async (
  context: AuthContext,
  user: AuthUser,
  references: ReferenceDates,
  containerIds: Set<string>,
): Promise<Map<string, SinceReferenceCounter>> => {
  const result = new Map<string, SinceReferenceCounter>();
  if (references.size === 0) return result;
  const containerReferences: ReferenceDates = new Map([...references.entries()].filter(([id]) => containerIds.has(id)));
  const [relationships, updates, containerObjects] = await Promise.all([
    countNewRelationships(context, user, references),
    countUpdates(context, user, references),
    containerReferences.size > 0 ? countNewContainerObjects(context, user, containerReferences) : Promise.resolve(new Map<string, number>()),
  ]);
  references.forEach((_, id) => {
    result.set(id, {
      relationships: relationships.get(id) ?? 0,
      updates: updates.get(id) ?? 0,
      containerObjects: containerObjects.get(id) ?? 0,
    });
  });
  return result;
};
