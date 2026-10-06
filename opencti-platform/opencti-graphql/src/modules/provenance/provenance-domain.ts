import * as R from 'ramda';
import { storeLoadByIdWithRefs, updateAttribute } from '../../database/middleware';
import { elAggregationCount, elCount, elFilteredAggregations } from '../../database/engine';
import { lockResources } from '../../lock/master-lock';
import { getDraftContext } from '../../utils/draftContext';
import { READ_STIX_DATA_WITH_INFERRED } from '../../database/utils';
import { FunctionalError, ForbiddenAccess } from '../../config/errors';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ENTITY_TYPE_IDENTITY,
} from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { isStixCoreRelationship, STIX_CORE_RELATIONSHIPS } from '../../schema/stixCoreRelationship';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { entitySettingEditField, findByType as findEntitySettingByType } from '../entitySetting/entitySetting-domain';
import { AccessOperation, filterMembersUsersWithUsersOrgs, RESTRICTED_USER, validateUserAccessOperation } from '../../utils/access';
import { controlUserConfidenceAgainstElement } from '../../utils/confidence-level';
import { publishUserAction } from '../../listener/UserActionListener';
import {
  EditOperation,
  type FilterGroup,
  FilterMode,
  FilterOperator,
  type QueryProvenanceFreshnessDistributionArgs,
  type QueryProvenanceSingleSourcedByTypeArgs,
  type QueryProvenanceSourceKindsDistributionArgs,
  type QueryProvenanceStatisticsArgs,
  type QueryProvenanceTypeStatisticsArgs,
  type MutationProvenanceRelationshipTrackingEditArgs,
} from '../../generated/graphql';
import { now } from '../../utils/format';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreObject, StoreObject } from '../../types/store';
import { addProvenanceConflictAdoptionCount } from '../../manager/telemetryManager';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from '../managerConfiguration/managerConfiguration-types';
import { buildConflictValue, conflictFieldLabel, isConflictTrackedAttribute, normalizeConflictValue } from './provenance-conflicts';
import { isProcedureRelationship, procedureMatchKey } from './provenance-procedures';
import { resolveCurrentValueOwner } from './provenance-upsert';
import { applyProvenanceUpdate, isProvenanceTrackedType, recordUpsertProvenance } from './provenance-write';
import { getProvenanceBackfillState, restartProvenanceBackfill } from './provenance-backfill';
import {
  ENTITY_SETTING_PROVENANCE_RELATIONSHIP_TYPES,
  isProvenanceTrackedForType,
  listProvenanceTrackedTypes,
  parseProvenanceRelationshipTypes,
  restrictToTrackedTypes,
  serializeProvenanceRelationshipTypes,
} from './provenance-tracking';
import { PROVENANCE_ENABLED } from './provenance-config';
import {
  ASSERTION_SOURCE_KINDS,
  ATTRIBUTE_ASSERTION_SOURCE_KINDS,
  ATTRIBUTE_LAST_ASSERTED_AT,
  PROVENANCE_BACKFILL_MANAGER_ID,
  VIRTUAL_FRESHNESS_DAYS,
  ATTRIBUTE_CONFLICTS,
  ATTRIBUTE_CORROBORATION_COUNT,
  ATTRIBUTE_FRESHNESS_STALE,
  ATTRIBUTE_HAS_CONFLICTS,
  ATTRIBUTE_PROCEDURES,
  ATTRIBUTE_SINGLE_SOURCED,
  SOURCE_KIND_AUTHOR,
  SOURCE_KIND_USER,
  type StoreAssertion,
  type StoreConflict,
  type StoreConflictValue,
  type StoreProcedure,
} from './provenance-types';

const DAY_IN_MS = 24 * 60 * 60 * 1000;
// Upper bound of concrete types in one statistics query: every domain object, observable and relationship type fits
const MAX_STATISTICS_TYPES = 500;
const PROVENANCE_RELATIONSHIP_TRACKING_LOCK = 'provenance_relationship_tracking';

export const computeFreshnessDays = (lastAssertedAt: string | Date | null | undefined, reference: Date = new Date()): number | null => {
  if (!lastAssertedAt) {
    return null;
  }
  const last = new Date(lastAssertedAt).getTime();
  if (Number.isNaN(last)) {
    return null;
  }
  return Math.max(0, Math.floor((reference.getTime() - last) / DAY_IN_MS));
};

// region read side: names are display labels, resolved with the reader rights
type NamedSource = { source_id: string; source_kind?: string | null; source_name?: string | null };

const resolveSourceNames = async <T extends NamedSource>(context: AuthContext, user: AuthUser, sources: T[]): Promise<T[]> => {
  const userSources = sources.filter((source) => source.source_kind === SOURCE_KIND_USER);
  const authorSources = sources.filter((source) => source.source_kind === SOURCE_KIND_AUTHOR);
  const visibleNames = new Map<string, string>();
  if (userSources.length > 0 && context.batch) {
    const creators = await Promise.all(userSources.map((source) => context.batch?.creatorBatchLoader.load(source.source_id)));
    const members = creators.filter((creator) => creator !== undefined && creator !== null);
    const visibleMembers = await filterMembersUsersWithUsersOrgs(context, user, members);
    visibleMembers.forEach((member) => visibleNames.set(member.id, member.name));
  }
  if (authorSources.length > 0 && context.batch) {
    const identities = await Promise.all(authorSources.map((source) => context.batch?.idsBatchLoader.load({ id: source.source_id, type: ENTITY_TYPE_IDENTITY })));
    identities.forEach((identity, index) => {
      if (identity) {
        visibleNames.set(authorSources[index].source_id, identity.name);
      }
    });
  }
  return sources.map((source) => {
    if (source.source_kind !== SOURCE_KIND_USER && source.source_kind !== SOURCE_KIND_AUTHOR) {
      return source;
    }
    return { ...source, source_name: visibleNames.get(source.source_id) ?? RESTRICTED_USER.name };
  });
};

export const resolveAssertionsForUser = async (context: AuthContext, user: AuthUser, assertions: StoreAssertion[] | null | undefined) => {
  if (!assertions || assertions.length === 0) {
    return [];
  }
  const sorted = [...assertions].sort((a, b) => b.last_asserted_at.localeCompare(a.last_asserted_at));
  return resolveSourceNames(context, user, sorted);
};

export const resolveConflictsForUser = async (
  context: AuthContext,
  user: AuthUser,
  conflicts: StoreConflict[] | null | undefined,
  entityType?: string,
) => {
  if (!conflicts || conflicts.length === 0) {
    return [];
  }
  const values = conflicts.flatMap((conflict) => conflict.values ?? []);
  const named = await resolveSourceNames(context, user, values);
  const namedByHash = new Map(named.map((value) => [`${value.source_id}:${value.value_hash}`, value]));
  return conflicts.map((conflict) => ({
    ...conflict,
    field_label: conflictFieldLabel(entityType, conflict.field),
    values: (conflict.values ?? [])
      .map((value) => namedByHash.get(`${value.source_id}:${value.value_hash}`) ?? value)
      .sort((a, b) => b.last_asserted_at.localeCompare(a.last_asserted_at)),
  }));
};
// endregion

// region statistics
const DEFAULT_STATISTICS_TYPES = [ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP];

const withFilter = (filters: FilterGroup | null | undefined, filter: FilterGroup['filters'][number]): FilterGroup => ({
  mode: FilterMode.And,
  filters: [filter],
  filterGroups: filters ? [filters] : [],
});

/**
 * Statistics only cover the types whose provenance is tracked: an untracked type has no source to count and would
 * only inflate the totals and the "never asserted" share. An abstract type stands for its tracked concrete types.
 */
export const resolveStatisticsTypes = (types: string[] | null | undefined, trackedTypes: string[]) => {
  return restrictToTrackedTypes(types && types.length > 0 ? types : DEFAULT_STATISTICS_TYPES, trackedTypes);
};

// Disabled provenance answers every statistic empty, without reading the entity settings nor counting anything
const statisticsTypes = async (context: AuthContext, types: string[] | null | undefined) => {
  if (!PROVENANCE_ENABLED) {
    return [];
  }
  return resolveStatisticsTypes(types, await listProvenanceTrackedTypes(context));
};

export const provenanceStatistics = async (context: AuthContext, user: AuthUser, args: QueryProvenanceStatisticsArgs) => {
  const types = await statisticsTypes(context, args.types);
  if (types.length === 0) {
    return { total: 0, with_provenance: 0, single_sourced: 0, corroborated: 0, with_conflicts: 0, stale: 0 };
  }
  const baseFilters = args.filters ?? null;
  const count = (filters: FilterGroup | null) => elCount(context, user, READ_STIX_DATA_WITH_INFERRED, { types, filters });
  const [total, withProvenance, single, corroborated, withConflicts, stale] = await Promise.all([
    count(baseFilters),
    count(withFilter(baseFilters, { key: [ATTRIBUTE_CORROBORATION_COUNT], values: [], operator: FilterOperator.NotNil })),
    count(withFilter(baseFilters, { key: [ATTRIBUTE_SINGLE_SOURCED], values: ['true'] })),
    count(withFilter(baseFilters, { key: [ATTRIBUTE_CORROBORATION_COUNT], values: ['2'], operator: FilterOperator.Gte })),
    count(withFilter(baseFilters, { key: [ATTRIBUTE_HAS_CONFLICTS], values: ['true'] })),
    count(withFilter(baseFilters, { key: [ATTRIBUTE_FRESHNESS_STALE], values: ['true'] })),
  ]);
  return { total, with_provenance: withProvenance, single_sourced: single, corroborated, with_conflicts: withConflicts, stale };
};

// Freshness buckets, in days since the last assertion of any source (bounds included)
const UNKNOWN_FRESHNESS_BUCKET = 'unknown';
export const FRESHNESS_BUCKETS: Array<{ bucket: string; from: number; to: number | null }> = [
  { bucket: '0-30', from: 0, to: 30 },
  { bucket: '31-90', from: 31, to: 90 },
  { bucket: '91-180', from: 91, to: 180 },
  { bucket: '181-365', from: 181, to: 365 },
  { bucket: '366+', from: 366, to: null },
];

const freshnessBucketFilter = (bucket: { from: number; to: number | null }): FilterGroup => ({
  mode: FilterMode.And,
  filters: [
    { key: [VIRTUAL_FRESHNESS_DAYS], values: [String(bucket.from)], operator: FilterOperator.Gte },
    ...(bucket.to !== null ? [{ key: [VIRTUAL_FRESHNESS_DAYS], values: [String(bucket.to)], operator: FilterOperator.Lte }] : []),
  ],
  filterGroups: [],
});

const combineFilters = (base: FilterGroup | null | undefined, extra: FilterGroup): FilterGroup => ({
  mode: FilterMode.And,
  filters: [],
  filterGroups: base ? [base, extra] : [extra],
});

export const provenanceFreshnessDistribution = async (context: AuthContext, user: AuthUser, args: QueryProvenanceFreshnessDistributionArgs) => {
  const types = await statisticsTypes(context, args.types);
  if (types.length === 0) {
    return [...FRESHNESS_BUCKETS.map((bucket) => ({ label: bucket.bucket, value: 0 })), { label: UNKNOWN_FRESHNESS_BUCKET, value: 0 }];
  }
  const count = (filters: FilterGroup) => elCount(context, user, READ_STIX_DATA_WITH_INFERRED, { types, filters });
  const counts = await Promise.all(FRESHNESS_BUCKETS.map((bucket) => count(combineFilters(args.filters, freshnessBucketFilter(bucket)))));
  const unknown = await count(combineFilters(args.filters, {
    mode: FilterMode.And,
    filters: [{ key: [ATTRIBUTE_LAST_ASSERTED_AT], values: [], operator: FilterOperator.Nil }],
    filterGroups: [],
  }));
  return [...FRESHNESS_BUCKETS.map((bucket, index) => ({ label: bucket.bucket, value: counts[index] })), { label: UNKNOWN_FRESHNESS_BUCKET, value: unknown }];
};

export const provenanceSourceKindsDistribution = async (context: AuthContext, user: AuthUser, args: QueryProvenanceSourceKindsDistributionArgs) => {
  const types = await statisticsTypes(context, args.types);
  if (types.length === 0) {
    return ASSERTION_SOURCE_KINDS.map((kind) => ({ source_kind: kind, count: 0 }));
  }
  const counts = await Promise.all(ASSERTION_SOURCE_KINDS.map((kind) => elCount(context, user, READ_STIX_DATA_WITH_INFERRED, {
    types,
    filters: combineFilters(args.filters, { mode: FilterMode.And, filters: [{ key: [ATTRIBUTE_ASSERTION_SOURCE_KINDS], values: [kind] }], filterGroups: [] }),
  })));
  return ASSERTION_SOURCE_KINDS.map((kind, index) => ({ source_kind: kind, count: counts[index] }));
};

/**
 * Share of single-sourced knowledge per entity type, among the knowledge with provenance.
 */
export const provenanceSingleSourcedByType = async (context: AuthContext, user: AuthUser, args: QueryProvenanceSingleSourcedByTypeArgs) => {
  const types = await statisticsTypes(context, args.types);
  if (types.length === 0) {
    return [];
  }
  const aggregate = (filters: FilterGroup) => elAggregationCount(context, user, READ_STIX_DATA_WITH_INFERRED, {
    types,
    field: 'entity_type',
    filters,
    convertEntityTypeLabel: true,
  });
  const withProvenance = { mode: FilterMode.And, filters: [{ key: [ATTRIBUTE_CORROBORATION_COUNT], values: [], operator: FilterOperator.NotNil }], filterGroups: [] };
  const single = { mode: FilterMode.And, filters: [{ key: [ATTRIBUTE_SINGLE_SOURCED], values: ['true'] }], filterGroups: [] };
  const [totals, singles] = await Promise.all([
    aggregate(combineFilters(args.filters, withProvenance)),
    aggregate(combineFilters(args.filters, single)),
  ]);
  const singleByType = new Map(singles.map((entry) => [entry.label, entry.count]));
  return totals
    .map((entry) => ({ entity_type: entry.label, total: entry.count, single_sourced: singleByType.get(entry.label) ?? 0 }))
    .sort((a, b) => b.total - a.total);
};
// endregion

// region configuration
const typesByAggregationKey = () => {
  const candidates = [
    ...schemaTypesDefinition.get(ABSTRACT_STIX_DOMAIN_OBJECT),
    ...schemaTypesDefinition.get(ABSTRACT_STIX_CYBER_OBSERVABLE),
    ...STIX_CORE_RELATIONSHIPS,
    STIX_SIGHTING_RELATIONSHIP,
  ];
  return new Map(candidates.map((type) => [type.toLowerCase(), type]));
};

/**
 * Per concrete type of the given types (an abstract type stands for its concrete types): the elements with recorded
 * sources, the corroborated ones and the last assertion, shown next to the tracking switches of the customization.
 */
export const provenanceTypeStatistics = async (context: AuthContext, user: AuthUser, args: QueryProvenanceTypeStatisticsArgs) => {
  if (!PROVENANCE_ENABLED || args.types.length === 0) {
    return [];
  }
  const withProvenance: FilterGroup = {
    mode: FilterMode.And,
    filters: [{ key: [ATTRIBUTE_CORROBORATION_COUNT], values: [], operator: FilterOperator.NotNil }],
    filterGroups: [],
  };
  const aggregations = await elFilteredAggregations(context, user, READ_STIX_DATA_WITH_INFERRED, { types: args.types, filters: withProvenance }, {
    by_type: {
      terms: { field: 'entity_type.keyword', size: MAX_STATISTICS_TYPES },
      aggs: {
        corroborated: { filter: { range: { [ATTRIBUTE_CORROBORATION_COUNT]: { gte: 2 } } } },
        last_asserted_at: { max: { field: ATTRIBUTE_LAST_ASSERTED_AT } },
      },
    },
  });
  const types = typesByAggregationKey();
  const buckets: Array<{ key: string; doc_count: number; corroborated: { doc_count: number }; last_asserted_at: { value: number | null } }> = aggregations.by_type?.buckets ?? [];
  return buckets.map((bucket) => ({
    entity_type: types.get(String(bucket.key).toLowerCase()) ?? String(bucket.key),
    with_provenance: bucket.doc_count,
    corroborated: bucket.corroborated.doc_count,
    last_asserted_at: bucket.last_asserted_at.value ? new Date(bucket.last_asserted_at.value).toISOString() : null,
  }));
};

/**
 * Tracks, or stops tracking, the provenance of the given relationship types; the other types keep their tracking.
 */
export const provenanceRelationshipTrackingEdit = async (context: AuthContext, user: AuthUser, args: MutationProvenanceRelationshipTrackingEditArgs) => {
  const relationshipTypes = R.uniq(args.relationship_types);
  // Tracking is set per concrete type: the abstract type is not a type any relationship has
  const unsupported = relationshipTypes.filter((type) => type === ABSTRACT_STIX_CORE_RELATIONSHIP || !isStixCoreRelationship(type));
  if (relationshipTypes.length === 0 || unsupported.length > 0) {
    throw FunctionalError('Provenance tracking is configured on relationship types', { types: unsupported });
  }
  const lock = await lockResources([PROVENANCE_RELATIONSHIP_TRACKING_LOCK]);
  try {
    const entitySetting = await findEntitySettingByType(context, user, ABSTRACT_STIX_CORE_RELATIONSHIP);
    if (!entitySetting) {
      throw FunctionalError('The entity setting of relationships does not exist');
    }
    const tracking = {
      ...parseProvenanceRelationshipTypes(entitySetting.provenance_relationship_types),
      ...Object.fromEntries(relationshipTypes.map((type) => [type, args.tracked])),
    };
    const input = [{ key: ENTITY_SETTING_PROVENANCE_RELATIONSHIP_TYPES, value: [serializeProvenanceRelationshipTypes(tracking)] }];
    return await entitySettingEditField(context, user, entitySetting.id, input);
  } finally {
    await lock.unlock();
  }
};
// endregion

// region backfill
export const provenanceBackfillStatus = async (context: AuthContext) => {
  return getProvenanceBackfillState(context);
};

export const provenanceBackfillRestart = async (context: AuthContext, user: AuthUser) => {
  const state = await restartProvenanceBackfill(context);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'restarts the provenance backfill',
    context_data: { id: PROVENANCE_BACKFILL_MANAGER_ID, entity_type: ENTITY_TYPE_MANAGER_CONFIGURATION, input: {} },
  });
  return state;
};
// endregion

// region analyst actions
const loadTrackedElement = async (context: AuthContext, user: AuthUser, id: string) => {
  const element = await storeLoadByIdWithRefs<StoreObject>(context, user, id);
  if (!element || !isProvenanceTrackedType(element.entity_type)) {
    throw FunctionalError('Cannot find the element to curate', { id });
  }
  return element;
};

// Retained provenance stays readable, but it is only curated while provenance is tracked for the element type
const loadEditableTrackedElement = async (context: AuthContext, user: AuthUser, id: string) => {
  const element = await loadTrackedElement(context, user, id);
  if (!PROVENANCE_ENABLED || !(await isProvenanceTrackedForType(context, element.entity_type))) {
    throw FunctionalError('Provenance is not tracked for this element', { id });
  }
  if (!validateUserAccessOperation(user, element, AccessOperation.EDIT)) {
    throw ForbiddenAccess();
  }
  controlUserConfidenceAgainstElement(user, element);
  return element as StoreObject & Record<string, any>;
};

// Every proposal of a conflicting value: the same value proposed by several sources is kept once per source
const findConflictProposals = (element: Record<string, any>, field: string, valueHash: string): StoreConflictValue[] => {
  const conflict = ((element[ATTRIBUTE_CONFLICTS] ?? []) as StoreConflict[]).find((entry) => entry.field === field);
  const proposals = (conflict?.values ?? []).filter((candidate) => candidate.value_hash === valueHash);
  if (proposals.length === 0) {
    throw FunctionalError('Cannot find the conflicting value', { id: element.internal_id, field });
  }
  return proposals;
};

// History is read with the rights of each reader: user and author names are never written into it.
export const describeProposalSource = (proposal: Pick<StoreConflictValue, 'source_kind' | 'source_name' | 'source_id'>) => {
  if (proposal.source_kind === SOURCE_KIND_USER) {
    return 'a user source';
  }
  if (proposal.source_kind === SOURCE_KIND_AUTHOR) {
    return 'an author source';
  }
  return `\`${proposal.source_name ?? proposal.source_id}\``;
};

export const describeProposalSources = (proposals: Pick<StoreConflictValue, 'source_kind' | 'source_name' | 'source_id'>[]) => {
  return R.uniq(proposals.map(describeProposalSource)).join(', ');
};

const publishProvenanceAction = async (user: AuthUser, element: BasicStoreObject, message: string, input: Record<string, unknown>) => {
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message,
    context_data: { id: element.internal_id, entity_type: element.entity_type, input },
  });
};

/**
 * Replace the current value of a field by an alternative value proposed by another source.
 * The value change follows the regular update path (history, stream), the replaced value
 * becomes an alternative attributed to its owner.
 */
export const adoptConflictValue = async (context: AuthContext, user: AuthUser, id: string, field: string, valueHash: string) => {
  const loaded = await loadEditableTrackedElement(context, user, id);
  const attribute = schemaAttributesDefinition.getAttribute(loaded.entity_type, field);
  if (!attribute || !isConflictTrackedAttribute(attribute) || attribute.update === false) {
    throw FunctionalError('This field cannot be adopted from a source', { field });
  }
  // Same lock as the upserts from the read to the conflict cleanup: an upsert can neither replace the adopted
  // value in between nor have its proposal removed as the adopted one
  const lockIds = R.uniq([loaded.internal_id, loaded.standard_id]);
  const lock = await lockResources(lockIds, { draftId: getDraftContext(context, user) });
  let element;
  let proposals;
  try {
    element = await loadEditableTrackedElement(context, user, id);
    proposals = findConflictProposals(element, field, valueHash);
    const proposal = proposals.find((candidate) => candidate.value !== null && candidate.value !== undefined);
    if (!proposal?.value) {
      throw FunctionalError('This value is too large to be adopted, edit the field directly', { field });
    }
    const adoptedValue = JSON.parse(proposal.value);
    const currentValue = element[field];
    const owner = await resolveCurrentValueOwner(context, element, field);
    const edit = [{ key: field, value: [adoptedValue], operation: EditOperation.Replace }];
    await updateAttribute(context, user, element.internal_id, element.entity_type, edit, { locks: lockIds });
    const conflictsAdd = [];
    if (owner && currentValue !== null && currentValue !== undefined && normalizeConflictValue(attribute, currentValue) !== normalizeConflictValue(attribute, adoptedValue)) {
      conflictsAdd.push({ field, value: buildConflictValue(attribute, currentValue, owner.source, owner.confidence, now()) });
    }
    await applyProvenanceUpdate(context, element, { conflictsAdd, conflictsRemove: [{ field, value_hash: valueHash }] }, { refresh: true });
  } finally {
    await lock.unlock();
  }
  await publishProvenanceAction(user, element, `adopts the value proposed by ${describeProposalSources(proposals)} for \`${field}\``, { field, value_hash: valueHash });
  await addProvenanceConflictAdoptionCount();
  return loadTrackedElement(context, user, element.internal_id);
};

/**
 * The analyst confirms the element is still valid: the analyst becomes (or refreshes) one of its sources,
 * which resets its freshness like any re-assertion.
 */
export const assertElement = async (context: AuthContext, user: AuthUser, id: string) => {
  const element = await loadEditableTrackedElement(context, user, id);
  const source = { source_id: user.id, source_kind: SOURCE_KIND_USER, source_name: user.name, work_id: null } as const;
  // Same lock as the upserts, so that a freshness policy is never applied after this confirmation (see applyFreshnessPolicy)
  const lock = await lockResources(R.uniq([element.internal_id, element.standard_id]), { draftId: getDraftContext(context, user) });
  let recorded;
  try {
    recorded = await recordUpsertProvenance(context, user, element, { source, input: {}, confidence: element.confidence ?? null }, { refresh: true, force: true });
  } finally {
    await lock.unlock();
  }
  if (!recorded) {
    throw FunctionalError('Provenance cannot be recorded on this element', { id });
  }
  await publishProvenanceAction(user, element, 'confirms the element is still valid', {});
  return loadTrackedElement(context, user, element.internal_id);
};

export const dismissConflictValue = async (context: AuthContext, user: AuthUser, id: string, field: string, valueHash: string) => {
  const loaded = await loadEditableTrackedElement(context, user, id);
  // Same lock as the upserts from the read to the removal: the proposals removed are exactly the ones named in the history
  const lock = await lockResources(R.uniq([loaded.internal_id, loaded.standard_id]), { draftId: getDraftContext(context, user) });
  let element;
  let proposals;
  try {
    element = await loadEditableTrackedElement(context, user, id);
    proposals = findConflictProposals(element, field, valueHash);
    await applyProvenanceUpdate(context, element, { conflictsRemove: [{ field, value_hash: valueHash }] }, { refresh: true });
  } finally {
    await lock.unlock();
  }
  await publishProvenanceAction(user, element, `dismisses the value proposed by ${describeProposalSources(proposals)} for \`${field}\``, { field, value_hash: valueHash });
  return loadTrackedElement(context, user, element.internal_id);
};

/**
 * Use one of the preserved procedures as the description of a uses relationship.
 */
export const adoptProcedure = async (context: AuthContext, user: AuthUser, id: string, text: string) => {
  const element = await loadEditableTrackedElement(context, user, id);
  if (!isProcedureRelationship(element.entity_type, element.toType)) {
    throw FunctionalError('Procedures only exist on uses relationships to attack patterns', { id });
  }
  const key = procedureMatchKey(text);
  const procedure = ((element[ATTRIBUTE_PROCEDURES] ?? []) as StoreProcedure[]).find((candidate) => procedureMatchKey(candidate.text) === key);
  if (!procedure) {
    throw FunctionalError('Cannot find the procedure', { id });
  }
  await updateAttribute(context, user, element.internal_id, element.entity_type, [{ key: 'description', value: [procedure.text], operation: EditOperation.Replace }]);
  return loadTrackedElement(context, user, element.internal_id);
};
// endregion
