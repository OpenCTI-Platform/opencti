import { storeLoadByIdWithRefs, updateAttribute } from '../../database/middleware';
import { elCount } from '../../database/engine';
import { READ_STIX_DATA_WITH_INFERRED } from '../../database/utils';
import { FunctionalError, ForbiddenAccess } from '../../config/errors';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP, ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { AccessOperation, filterMembersUsersWithUsersOrgs, RESTRICTED_USER, validateUserAccessOperation } from '../../utils/access';
import { controlUserConfidenceAgainstElement } from '../../utils/confidence-level';
import { publishUserAction } from '../../listener/UserActionListener';
import { EditOperation, type FilterGroup, FilterMode, FilterOperator, type QueryProvenanceStatisticsArgs } from '../../generated/graphql';
import { now } from '../../utils/format';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreObject, StoreObject } from '../../types/store';
import { buildConflictValue, isConflictTrackedAttribute, normalizeConflictValue } from './provenance-conflicts';
import { isProcedureRelationship, procedureMatchKey } from './provenance-procedures';
import { resolveCurrentValueOwner } from './provenance-upsert';
import { applyProvenanceUpdate, isProvenanceTrackedType } from './provenance-write';
import {
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

export const resolveConflictsForUser = async (context: AuthContext, user: AuthUser, conflicts: StoreConflict[] | null | undefined) => {
  if (!conflicts || conflicts.length === 0) {
    return [];
  }
  const values = conflicts.flatMap((conflict) => conflict.values ?? []);
  const named = await resolveSourceNames(context, user, values);
  const namedByHash = new Map(named.map((value) => [`${value.source_id}:${value.value_hash}`, value]));
  return conflicts.map((conflict) => ({
    ...conflict,
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

export const provenanceStatistics = async (context: AuthContext, user: AuthUser, args: QueryProvenanceStatisticsArgs) => {
  const types = args.types && args.types.length > 0 ? args.types : DEFAULT_STATISTICS_TYPES;
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
// endregion

// region analyst actions
const loadTrackedElement = async (context: AuthContext, user: AuthUser, id: string) => {
  const element = await storeLoadByIdWithRefs<StoreObject>(context, user, id);
  if (!element || !isProvenanceTrackedType(element.entity_type)) {
    throw FunctionalError('Cannot find the element to curate', { id });
  }
  return element;
};

const loadEditableTrackedElement = async (context: AuthContext, user: AuthUser, id: string) => {
  const element = await loadTrackedElement(context, user, id);
  if (!validateUserAccessOperation(user, element, AccessOperation.EDIT)) {
    throw ForbiddenAccess();
  }
  controlUserConfidenceAgainstElement(user, element);
  return element as StoreObject & Record<string, any>;
};

const findConflictValue = (element: Record<string, any>, field: string, valueHash: string): StoreConflictValue => {
  const conflict = ((element[ATTRIBUTE_CONFLICTS] ?? []) as StoreConflict[]).find((entry) => entry.field === field);
  const value = conflict?.values?.find((candidate) => candidate.value_hash === valueHash);
  if (!value) {
    throw FunctionalError('Cannot find the conflicting value', { id: element.internal_id, field });
  }
  return value;
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
  const element = await loadEditableTrackedElement(context, user, id);
  const attribute = schemaAttributesDefinition.getAttribute(element.entity_type, field);
  if (!attribute || !isConflictTrackedAttribute(attribute) || attribute.update === false) {
    throw FunctionalError('This field cannot be adopted from a source', { field });
  }
  const proposal = findConflictValue(element, field, valueHash);
  if (proposal.value === null || proposal.value === undefined) {
    throw FunctionalError('This value is too large to be adopted, edit the field directly', { field });
  }
  const adoptedValue = JSON.parse(proposal.value);
  const currentValue = element[field];
  const owner = await resolveCurrentValueOwner(context, element, field);
  await updateAttribute(context, user, element.internal_id, element.entity_type, [{ key: field, value: [adoptedValue], operation: EditOperation.Replace }]);
  const conflictsAdd = [];
  if (owner && currentValue !== null && currentValue !== undefined && normalizeConflictValue(attribute, currentValue) !== normalizeConflictValue(attribute, adoptedValue)) {
    conflictsAdd.push({ field, value: buildConflictValue(attribute, currentValue, owner.source, owner.confidence, now()) });
  }
  await applyProvenanceUpdate(context, element, { conflictsAdd, conflictsRemove: [{ field, value_hash: valueHash }] }, { refresh: true });
  await publishProvenanceAction(user, element, `adopts the value proposed by \`${proposal.source_name ?? proposal.source_id}\` for \`${field}\``, { field, value_hash: valueHash });
  return loadTrackedElement(context, user, element.internal_id);
};

export const dismissConflictValue = async (context: AuthContext, user: AuthUser, id: string, field: string, valueHash: string) => {
  const element = await loadEditableTrackedElement(context, user, id);
  const proposal = findConflictValue(element, field, valueHash);
  await applyProvenanceUpdate(context, element, { conflictsRemove: [{ field, value_hash: valueHash }] }, { refresh: true });
  await publishProvenanceAction(user, element, `dismisses the value proposed by \`${proposal.source_name ?? proposal.source_id}\` for \`${field}\``, { field, value_hash: valueHash });
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
