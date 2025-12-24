import * as R from 'ramda';
import {
  buildPagination,
  isEmptyField,
  isNotEmptyField,
  READ_DATA_INDICES,
  READ_DATA_INDICES_WITHOUT_INFERRED,
  READ_RELATIONSHIPS_INDICES,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
} from './utils';
import {
  computeQueryIndices,
  elAggregationNestedTermsWithFilter,
  elAggregationsList,
  elCount,
  elFindByIds,
  elList,
  elConnection,
  elLoadById,
  elPaginate,
  ES_DEFAULT_PAGINATION,
  UNIMPACTED_ENTITIES_ROLE,
  type ElFindByIdsOpts,
} from './engine';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_OBJECT, ABSTRACT_STIX_RELATIONSHIP, buildRefRelationKey } from '../schema/general';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreBase, BasicStoreCommon, BasicStoreEntity, BasicStoreObject, BasicStoreRelation, BasicConnection, StoreProxyRelation } from '../types/store';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { type Filter, type FilterGroup, FilterMode, FilterOperator, type InputMaybe, OrderingMode } from '../generated/graphql';
import {
  ASSIGNEE_FILTER,
  CREATOR_FILTER,
  ID_SUBFILTER,
  INSTANCE_REGARDING_OF,
  INSTANCE_REGARDING_OF_DIRECTION_FORCED,
  INSTANCE_REGARDING_OF_DIRECTION_REVERSE,
  PARTICIPANT_FILTER,
  RELATION_TYPE_SUBFILTER,
} from '../utils/filtering/filtering-constants';
import type { UserReadActionContextData } from '../listener/UserActionListener';
import { completeContextDataForEntity, publishUserAction } from '../listener/UserActionListener';
import { extractEntityRepresentativeName } from './entity-representative';
import { asyncMap } from '../utils/data-processing';
import { isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';

export interface FiltersWithNested extends Filter {
  nested?: Array<{
    key: string; // nested filters handle special cases for elastic, it's an internal format
    values: string[];
    operator?: FilterOperator;
    mode?: FilterMode;
  }>;
}

export interface FilterGroupWithNested extends FilterGroup {
  filters: FiltersWithNested[];
  filterGroups: FilterGroupWithNested[];
}

export interface ListFilter<T extends BasicStoreCommon> {
  indices?: Array<string>;
  search?: InputMaybe<string> | string | undefined;
  useWildcardPrefix?: boolean;
  first?: number | null;
  after?: string | undefined | null;
  orderBy?: any;
  baseData?: boolean;
  orderMode?: InputMaybe<OrderingMode>;
  filters?: FilterGroupWithNested | null;
  noFiltersChecking?: boolean;
  callback?: (result: Array<T>) => Promise<boolean | void>;
}

// entities
export interface EntityFilters<T extends BasicStoreCommon> extends ListFilter<T> {
  fromOrToId?: string | Array<string>;
  fromId?: string | Array<string>;
  fromRole?: string;
  toId?: string | Array<string>;
  toRole?: string;
  fromTypes?: Array<string>;
  toTypes?: Array<string>;
  types?: Array<string>;
  relationshipTypes?: Array<string>;
  elementWithTargetTypes?: Array<string>;
  filters?: FilterGroupWithNested | null;
}

export interface EntityOptions<T extends BasicStoreCommon> extends EntityFilters<T> {
  ids?: Array<string>;
  indices?: Array<string>;
  includeAuthorities?: boolean | null;
  withInferences?: boolean;
  includeDeletedInDraft?: boolean | null;
}

// relations
export interface RelationFilters<T extends BasicStoreCommon> extends ListFilter<T> {
  relationFilter?: {
    relation: string;
    id: string;
    relationId: string;
  };
  isTo?: boolean | null;
  fromOrToId?: string | Array<string>;
  fromId?: string | Array<string>;
  fromRole?: string;
  toId?: string | Array<string>;
  toRole?: string;
  fromTypes?: Array<string>;
  toTypes?: Array<string>;
  elementWithTargetTypes?: Array<string>;
  startTimeStart?: string;
  startTimeStop?: string;
  stopTimeStart?: string;
  stopTimeStop?: string;
  firstSeenStart?: string;
  firstSeenStop?: string;
  lastSeenStart?: string;
  lastSeenStop?: string;
  startDate?: string;
  endDate?: string;
  confidences?: Array<string>;
}

export interface RelationOptions<T extends BasicStoreCommon> extends RelationFilters<T> {
  indices?: Array<string>;
  baseData?: boolean;
  withInferences?: boolean;
}

export const buildAggregationFilter = <T extends BasicStoreCommon>(args: RelationFilters<T>) => {
  const { fromOrToId = [], isTo = null } = args;
  const { fromId, fromRole, fromTypes = [] } = args;
  const { toId, toRole, toTypes = [] } = args;
  const filtersContent = [];
  const nestedElement = [];
  const optsFromOrToIdIds = Array.isArray(fromOrToId) ? fromOrToId : [fromOrToId];
  if (fromOrToId && optsFromOrToIdIds.length > 0) {
    nestedElement.push({ key: 'internal_id', values: optsFromOrToIdIds, operator: 'not_eq' });
    filtersContent.push({ key: 'connections', nested: nestedElement });
  }
  if (isTo === false) {
    const nestedFrom = [];
    if (fromId) {
      nestedFrom.push({ key: 'internal_id', values: Array.isArray(fromId) ? fromId : [fromId] });
    }
    if (fromTypes && fromTypes.length > 0) {
      nestedFrom.push({ key: 'types', values: fromTypes });
    }
    if (fromRole) {
      nestedFrom.push({ key: 'role', values: [fromRole] });
    } else {
      nestedFrom.push({ key: 'role', values: ['*_from'], operator: 'wildcard' });
    }
    filtersContent.push({ key: 'connections', nested: nestedFrom });
  }
  if (isTo === true) {
    const nestedTo = [];
    if (toId) {
      nestedTo.push({ key: 'internal_id', values: Array.isArray(toId) ? toId : [toId] });
    }
    if (toTypes && toTypes.length > 0) {
      nestedTo.push({ key: 'types', values: toTypes });
    }
    if (toRole) {
      nestedTo.push({ key: 'role', values: [toRole] });
    } else {
      nestedTo.push({ key: 'role', values: ['*_to'], operator: 'wildcard' });
    }
    filtersContent.push({ key: 'connections', nested: nestedTo });
  }
  return { filters: { mode: 'and', filters: filtersContent, filterGroups: [] } };
};

export const buildRelationsFilter = <T extends BasicStoreCommon>(relationTypes: string | Array<string> | undefined | null, args: RelationFilters<T>) => {
  const types = !relationTypes || isEmptyField(relationTypes) ? [ABSTRACT_STIX_CORE_RELATIONSHIP] : relationTypes;
  const {
    relationFilter,
    filters = undefined,
    fromOrToId = [],
    fromId,
    fromRole,
    toId,
    toRole,
    fromTypes = [],
    toTypes = [],
    elementWithTargetTypes = [],
  } = args;
  const {
    startTimeStart,
    startTimeStop,
    stopTimeStart,
    stopTimeStop,
    firstSeenStart,
    firstSeenStop,
    lastSeenStart,
    lastSeenStop,
    confidences = [],
  } = args;
  // Handle relation type(s)
  // 0 - Check if we can support the query by Elastic
  const filtersFromOptionsContent: FiltersWithNested[] = [];
  if (relationFilter) {
    const { relation, id, relationId } = relationFilter;
    filtersFromOptionsContent.push({ key: [buildRefRelationKey(relation)], values: [id] });
    if (relationId) {
      filtersFromOptionsContent.push({ key: ['internal_id'], values: [relationId] });
    }
  }
  // region element filtering
  const optsFromOrToIds = Array.isArray(fromOrToId) ? fromOrToId : [fromOrToId];
  if (fromOrToId && optsFromOrToIds.length > 0) {
    filtersFromOptionsContent.push({ key: ['fromOrToId'], values: optsFromOrToIds });
  }
  if (elementWithTargetTypes && isNotEmptyField(elementWithTargetTypes)) {
    filtersFromOptionsContent.push({ key: ['elementWithTargetTypes'], values: elementWithTargetTypes });
  }
  if (fromId && isNotEmptyField(fromId)) {
    filtersFromOptionsContent.push({ key: ['fromId'], values: Array.isArray(fromId) ? fromId : [fromId] });
  }
  if (fromRole && isNotEmptyField(fromRole)) {
    filtersFromOptionsContent.push({ key: ['fromRole'], values: [fromRole] });
  }
  if (fromTypes && isNotEmptyField(fromTypes)) {
    filtersFromOptionsContent.push({ key: ['fromTypes'], values: fromTypes });
  }
  if (toId && isNotEmptyField(toId)) {
    filtersFromOptionsContent.push({ key: ['toId'], values: Array.isArray(toId) ? toId : [toId] });
  }
  if (toRole && isNotEmptyField(toRole)) {
    filtersFromOptionsContent.push({ key: ['toRole'], values: [toRole] });
  }
  if (toTypes && isNotEmptyField(toTypes)) {
    filtersFromOptionsContent.push({ key: ['toTypes'], values: toTypes });
  }
  if (confidences && confidences.length > 0) {
    filtersFromOptionsContent.push({ key: ['confidence'], values: confidences });
  }
  // endregion
  // region relation filtering
  if (startTimeStart) filtersFromOptionsContent.push({ key: ['start_time'], values: [startTimeStart], operator: FilterOperator.Gt });
  if (startTimeStop) filtersFromOptionsContent.push({ key: ['start_time'], values: [startTimeStop], operator: FilterOperator.Lt });
  if (stopTimeStart) filtersFromOptionsContent.push({ key: ['stop_time'], values: [stopTimeStart], operator: FilterOperator.Gt });
  if (stopTimeStop) filtersFromOptionsContent.push({ key: ['stop_time'], values: [stopTimeStop], operator: FilterOperator.Lt });
  if (firstSeenStart) filtersFromOptionsContent.push({ key: ['first_seen'], values: [firstSeenStart], operator: FilterOperator.Gt });
  if (firstSeenStop) filtersFromOptionsContent.push({ key: ['first_seen'], values: [firstSeenStop], operator: FilterOperator.Lt });
  if (lastSeenStart) filtersFromOptionsContent.push({ key: ['last_seen'], values: [lastSeenStart], operator: FilterOperator.Gt });
  if (lastSeenStop) filtersFromOptionsContent.push({ key: ['last_seen'], values: [lastSeenStop], operator: FilterOperator.Lt });
  // if (startDate) filtersFromOptionsContent.push({ key: ['created_at'], values: [startDate], operator: FilterOperator.Gt });
  // if (endDate) filtersFromOptionsContent.push({ key: ['created_at'], values: [endDate], operator: FilterOperator.Lt });
  // remove options already passed in filters and useless for the next steps
  const cleanedArgs = R.pipe(
    R.dissoc('relationFilter'),
    R.dissoc('fromOrToId'),
    R.dissoc('fromId'),
    R.dissoc('fromRole'),
    R.dissoc('toId'),
    R.dissoc('toRole'),
    R.dissoc('fromTypes'),
    R.dissoc('toTypes'),
    R.dissoc('elementWithTargetTypes'),
    R.dissoc('startTimeStart'),
    R.dissoc('startTimeStop'),
    R.dissoc('stopTimeStart'),
    R.dissoc('stopTimeStop'),
    R.dissoc('firstSeenStart'),
    R.dissoc('firstSeenStop'),
    R.dissoc('lastSeenStart'),
    R.dissoc('lastSeenStop'),
    R.dissoc('confidences'),
  )(args);

  let computedFilters = filters;
  // Args filters must be wrapper on top of api filters
  if (filtersFromOptionsContent.length > 0) {
    computedFilters = {
      mode: FilterMode.And,
      filters: filtersFromOptionsContent,
      filterGroups: filters && isFilterGroupNotEmpty(filters) ? [filters] : [],
    };
  }
  return {
    ...cleanedArgs,
    types: Array.isArray(types) ? types : [types],
    filters: computedFilters,
  };
};

export const topRelationsList = async <T extends StoreProxyRelation>(context: AuthContext, user: AuthUser, type: string | Array<string>,
  args: RelationOptions<T> = {}): Promise<Array<T>> => {
  const { indices } = args;
  const computedIndices = computeQueryIndices(indices, type);
  const paginateArgs = buildRelationsFilter(type, args);
  return await elPaginate(context, user, computedIndices, { ...paginateArgs, connectionFormat: false }) as T[];
};

export const pageRelationsConnection = async <T extends BasicStoreRelation>(context: AuthContext, user: AuthUser, type: string | Array<string>,
  args: RelationOptions<T> = {}): Promise<BasicConnection<T>> => {
  const { indices } = args;
  const computedIndices = computeQueryIndices(indices, type);
  const paginateArgs = buildRelationsFilter(type, args);
  return await elPaginate(context, user, computedIndices, { ...paginateArgs, connectionFormat: true }) as BasicConnection<T>;
};

export const fullRelationsList = async <T extends BasicStoreRelation>(context: AuthContext, user: AuthUser, type: string | Array<string> | undefined | null,
  args: RelationOptions<T> = {}): Promise<Array<T>> => {
  const { indices } = args;
  const computedIndices = computeQueryIndices(indices, type, args.withInferences);
  const paginateArgs = buildRelationsFilter(type, args);
  return elList<T>(context, user, computedIndices, paginateArgs);
};

export const buildAggregationRelationFilter = <T extends BasicStoreCommon>(relationshipTypes: string | Array<string>, args: RelationFilters<T>) => {
  const searchOptions = buildRelationsFilter(relationshipTypes, args);
  const aggregationOptions = buildAggregationFilter(args);
  return { ...args, searchOptions, aggregationOptions };
};

// entities
export const buildEntityFilters = <T extends BasicStoreCommon>(entityTypes: string | Array<string> | undefined | null, args: EntityFilters<T> = {}) => {
  const types = !entityTypes || isEmptyField(entityTypes) ? [ABSTRACT_STIX_CORE_OBJECT] : entityTypes;
  return buildRelationsFilter(types, args);
};

export const buildThingsFilters = <T extends BasicStoreCommon>(thingTypes: string | Array<string> | undefined | null, args: RelationFilters<T> = {}) => {
  const types = !thingTypes || isEmptyField(thingTypes) ? [ABSTRACT_STIX_OBJECT, ABSTRACT_STIX_RELATIONSHIP] : thingTypes;
  return buildRelationsFilter(types, args);
};

const entitiesAggregations = [
  { name: CREATOR_FILTER, field: 'creator_id.keyword' },
  { name: ASSIGNEE_FILTER, field: 'rel_object-assignee.internal_id.keyword' },
  { name: PARTICIPANT_FILTER, field: 'rel_object-participant.internal_id.keyword' },
];
export const fullEntitiesThoughAggregationConnection = async (context: AuthContext, user: AuthUser, filter: string, type: string, args = {}) => {
  const aggregation = entitiesAggregations.find((agg) => agg.name === filter);
  if (!aggregation) {
    throw FunctionalError('Filter is not supported as an aggregation', { filter });
  }
  const aggregationsList = await elAggregationsList(context, user, READ_DATA_INDICES_WITHOUT_INFERRED, [aggregation], args);
  const values = aggregationsList.find((agg) => agg.name === filter)?.values ?? [];
  const nodeElements = values
    .sort((a: { value: string; label: string }, b: { value: string; label: string }) => a.label.localeCompare(b.label))
    .map((val: { value: string; label: string }) => ({ node: { id: val.value, name: val.label, entity_type: type } }));
  return buildPagination(0, null, nodeElements, nodeElements.length);
};

export const fullEntitiesList = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, entityTypes: Array<string> | null,
  args: EntityOptions<T> = {}): Promise<Array<T>> => {
  const { indices } = args;
  const computedIndices = computeQueryIndices(indices, entityTypes);
  const paginateArgs = buildEntityFilters(entityTypes, args);
  return elList(context, user, computedIndices, paginateArgs);
};

export interface FullEntitiesThroughRelation {
  type: string | string[];
  fromOrToId: string | string[];
  fromOrToType: string | string[];
  sourceSide: 'from' | 'to';
  withInferences: boolean;
  filters?: FilterGroupWithNested | null;
}

// This method is designed to fetch all entities
// If you need to paginate, order and sort, use pageEntitiesConnection
export const fullEntitiesListThroughRelations = async <T extends BasicStoreCommon>(context: AuthContext, user: AuthUser,
  relation: FullEntitiesThroughRelation): Promise<Array<T>> => {
  const { type, sourceSide, fromOrToId, fromOrToType, withInferences = false, filters: argsFilters } = relation;
  if (isEmptyField(fromOrToId) || isEmptyField(fromOrToType)) {
    return [];
  }
  const opposite = sourceSide === 'from' ? 'to' : 'from';
  const fromOrToIds = Array.isArray(fromOrToId) ? fromOrToId : [fromOrToId];
  // Filter on connection to get only relation coming from ids.
  const directionInternalIdFilter: FiltersWithNested = {
    key: ['connections'],
    values: [],
    nested: [
      { key: 'internal_id', values: fromOrToIds },
      { key: 'role', values: [`*_${relation.sourceSide}`], operator: FilterOperator.Wildcard },
    ],
  };
  // Filter the other side of the relation to have expected toEntityType
  const oppositeTypeFilter: FiltersWithNested = {
    key: ['connections'],
    values: [],
    nested: [
      { key: 'types', values: Array.isArray(fromOrToType) ? fromOrToType : [fromOrToType] },
      { key: 'role', values: [`*_${opposite}`], operator: FilterOperator.Wildcard },
    ],
  };
  const filters: FilterGroupWithNested = {
    mode: FilterMode.And,
    filters: [directionInternalIdFilter, oppositeTypeFilter],
    filterGroups: argsFilters ? [argsFilters] : [],
  };
  // region Resolve all relations (can be inferred or not)
  const indices = withInferences ? READ_RELATIONSHIPS_INDICES : READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED;
  const relations = await fullRelationsList<BasicStoreRelation>(context, user, type, {
    filters,
    indices,
    noFiltersChecking: true,
  });
  // region Resolved all targets for all relations
  const targetIds = R.uniq(relations.map((s) => s[`${opposite}Id`]));
  const targetTypes = R.uniq(relations.map((s) => s[`${opposite}Type`]));
  return await elFindByIds(context, user, targetIds, { type: targetTypes }) as unknown as Array<T>;
};

interface fullOptsList {
  withInferences?: boolean;
  filters?: FilterGroupWithNested | null;
}

export const fullEntitiesThroughRelationsToList = async <T extends BasicStoreCommon>(context: AuthContext, user: AuthUser,
  fromId: string | string[], relationship_type: string, toType: string | string[], opts: fullOptsList = {}): Promise<Array<T>> => {
  const rel: FullEntitiesThroughRelation = {
    type: relationship_type,
    fromOrToId: fromId,
    fromOrToType: toType,
    sourceSide: 'from',
    withInferences: opts.withInferences ?? false,
    filters: opts.filters,
  };
  return fullEntitiesListThroughRelations(context, user, rel);
};
export const fullEntitiesThroughRelationsFromList = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser,
  toId: string | string[], relationship_type: string, fromType: string | string[], opts: fullOptsList = {}): Promise<Array<T>> => {
  const rel: FullEntitiesThroughRelation = {
    type: relationship_type,
    fromOrToId: toId,
    fromOrToType: fromType,
    sourceSide: 'to',
    withInferences: opts.withInferences ?? false,
    filters: opts.filters,
  };
  return fullEntitiesListThroughRelations(context, user, rel);
};

export const pageEntitiesConnection = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, entityTypes: Array<string>,
  args: EntityOptions<T> = {}): Promise<BasicConnection<T>> => {
  const { indices } = args;
  const computedIndices = computeQueryIndices(indices, entityTypes);
  const first = args.first ?? ES_DEFAULT_PAGINATION;
  // maxSize MUST be aligned with first in this method.
  // As using elConnection is repaginate, removing maxSize will lead to major api breaking
  const paginateArgs = { ...buildEntityFilters(entityTypes, args), first, maxSize: first };
  const connection = await elConnection(context, user, computedIndices, paginateArgs);
  return connection as BasicConnection<T>;
};

export const topEntitiesList = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, entityTypes: string[], args: EntityOptions<T> = {}) => {
  const data = await pageEntitiesConnection(context, user, entityTypes, args);
  return asyncMap(data.edges, (edge) => edge.node);
};

export const pageRegardingEntitiesConnection = async <T extends BasicStoreEntity>(
  context: AuthContext,
  user: AuthUser,
  connectedEntityId: string | null,
  relationType: string,
  entityType: string | string[],
  reverse_relation: boolean,
  args: EntityOptions<T> = {},
): Promise<BasicConnection<T>> => {
  const entityTypes = Array.isArray(entityType) ? entityType : [entityType];
  if (UNIMPACTED_ENTITIES_ROLE.includes(`${relationType}_to`)) {
    throw UnsupportedError('List connected entities paginated cant be used', { type: entityType });
  }
  const connectedFilters: FilterGroup = {
    mode: FilterMode.And,
    filters: [
      {
        key: [INSTANCE_REGARDING_OF],
        values: [
          ...(connectedEntityId === null ? [] : [{ key: ID_SUBFILTER, values: [connectedEntityId] }]),
          { key: RELATION_TYPE_SUBFILTER, values: [relationType] },
          { key: INSTANCE_REGARDING_OF_DIRECTION_FORCED, values: [true] },
          { key: INSTANCE_REGARDING_OF_DIRECTION_REVERSE, values: [reverse_relation] },
        ],
      },
    ],
    filterGroups: args.filters && isFilterGroupNotEmpty(args.filters) ? [args.filters] : [],
  };
  return pageEntitiesConnection(context, user, entityTypes, { ...args, filters: connectedFilters });
};

export const findEntitiesIdsWithRelations = async (
  context: AuthContext,
  user: AuthUser,
  connectedEntitiesIds: string[],
  relationType: string,
  entityType: string | string[],
  reverse_relation: boolean,
) => {
  const entityTypes = Array.isArray(entityType) ? entityType : [entityType];
  const connectionRole = reverse_relation ? `${relationType}_to` : `${relationType}_from`;
  const connectionsFilters: FilterGroupWithNested = {
    mode: FilterMode.And,
    filters: [
      {
        key: ['connections'],
        values: [],
        nested: [
          { key: 'internal_id', values: connectedEntitiesIds },
          ...(reverse_relation ? [] : [{ key: 'types', values: entityTypes }]),
          { key: 'role', values: [connectionRole] },
        ],
      }],
    filterGroups: [],
  };
  // add a filter on role for aggregation to return only matching connections for the right role
  const aggFilter = {
    bool: { filter: [{ term: { 'connections.role.keyword': connectionRole } }] },
  };
  const aggSize = connectedEntitiesIds.length;
  const args = { filters: connectionsFilters, types: [relationType], size: aggSize };
  const aggregation = { field: 'connections.internal_id.keyword', path: 'connections', filter: aggFilter };
  const aggregationResult = await elAggregationNestedTermsWithFilter(context, user, READ_RELATIONSHIPS_INDICES, aggregation, args);
  const resultEntityIds = aggregationResult.map((agg: { label: string }) => agg.label)
    .filter((id: string) => connectedEntitiesIds.includes(id)); // keep only ids we were looking for
  return resultEntityIds;
};

export const loadEntityThroughRelationsPaginated = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, connectedEntityId: string,
  relationType: string, entityType: string | string[], reverse_relation: boolean): Promise<T> => {
  const args = { first: 1 };
  const pagination = await pageRegardingEntitiesConnection<T>(context, user, connectedEntityId, relationType, entityType, reverse_relation, args);
  return pagination.edges[0]?.node;
};

export const countAllThings = async <T extends BasicStoreCommon>(context: AuthContext, user: AuthUser, args: ListFilter<T> = {}) => {
  const { indices = READ_DATA_INDICES } = args;
  return elCount(context, user, indices, args);
};

export const internalFindByIds = async <T extends BasicStoreObject>(
  context: AuthContext,
  user: AuthUser,
  ids: string[],
  args?: {
    type?: string | string[];
    baseData?: boolean;
    toMap?: boolean;
    mapWithAllIds?: boolean;
    baseFields?: string[];
  } & ElFindByIdsOpts,
) => {
  return await elFindByIds<T>(context, user, ids, args);
};

// Similar to internalFindByIds but forcing toMap: true in type.
// To avoid types mismatch with internalFindByIds that cast the result into an array.
export const internalFindByIdsMapped = async <T extends BasicStoreObject>(
  context: AuthContext,
  user: AuthUser,
  ids: string[],
  args?: {
    type?: string | string[];
    baseData?: boolean;
    mapWithAllIds?: boolean;
    baseFields?: string[];
  } & Record<string, string | string[] | boolean>,
) => {
  return await elFindByIds(context, user, ids, { ...(args ?? {}), toMap: true }) as unknown as Record<string, T>;
};

export const internalLoadById = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  id: string | undefined,
  opts?: { type?: string | string[]; baseData?: boolean; indices?: string[] },
): Promise<T> => {
  return await elLoadById<T>(context, user, id ?? '', opts) as unknown as T;
};

export const storeLoadById = async <T extends BasicStoreCommon>(context: AuthContext, user: AuthUser, id: string, type: string | string[], opts = {}): Promise<T> => {
  if (R.isNil(type) || R.isEmpty(type)) {
    throw FunctionalError('You need to specify a type when loading an element', { id });
  }
  const data = await internalLoadById<T>(context, user, id, { ...opts, type });
  if (data) {
    const baseData = { id, entity_name: extractEntityRepresentativeName(data), entity_type: data.entity_type };
    const contextData: UserReadActionContextData = completeContextDataForEntity(baseData, data);
    await publishUserAction({
      user,
      event_type: 'read',
      event_access: 'extended',
      event_scope: 'read',
      context_data: contextData,
    });
  }
  return data;
};

export const storeLoadByIds = async <T extends BasicStoreBase>(context: AuthContext, user: AuthUser, ids: string[], type: string): Promise<T[]> => {
  if (R.isNil(type) || R.isEmpty(type)) {
    throw FunctionalError('You need to specify a type when loading elements', { ids });
  }
  const hits = await elFindByIds(context, user, ids, { type, indices: READ_DATA_INDICES });
  return ids.map((id) => (hits as T[]).find((h: T) => h.internal_id === id)) as T[];
};
