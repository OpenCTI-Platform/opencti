import * as R from 'ramda';
import {
  buildPagination,
  READ_DATA_INDICES,
  READ_DATA_INDICES_WITHOUT_INFERRED,
  READ_ENTITIES_INDICES,
  READ_RELATIONSHIPS_INDICES,
} from './utils';
import { elAggregationsList, elCount, elFindByIds, elList, elLoadById, elPaginate } from './engine';
import { buildRefRelationKey } from '../schema/general';
import type { AuthContext, AuthUser } from '../types/user';
import type {
  BasicStoreBase,
  BasicStoreCommon,
  BasicStoreEntity,
  BasicStoreObject,
  StoreEntityConnection,
  StoreProxyRelation
} from '../types/store';
import { FunctionalError, UnsupportedError } from '../config/errors';
import type { Filter, FilterGroup, InputMaybe, OrderingMode } from '../generated/graphql';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { ASSIGNEE_FILTER, CREATOR_FILTER, PARTICIPANT_FILTER } from '../utils/filtering/filtering-constants';
import { publishUserAction, type UserReadActionContextData } from '../listener/UserActionListener';
import { extractEntityRepresentativeName } from './entity-representative';
import {
  RELATION_CREATED_BY,
  RELATION_GRANTED_TO,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING
} from '../schema/stixRefRelationship';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';

export interface FiltersWithNested extends Filter {
  nested?: Array<{
    key: string; // nested filters handle special cases for elastic, it's an internal format
    values: string[];
    operator?: FilterOperator;
    mode?: FilterMode;
  }>;
}

export interface FilterGroupWithNested extends FilterGroup {
  filters: FiltersWithNested[],
  filterGroups: FilterGroupWithNested[],
}

export interface ListFilter<T extends BasicStoreCommon> {
  indices?: Array<string>;
  search?: InputMaybe<string> | string | undefined;
  useWildcardPrefix?: boolean;
  useWildcardSuffix?: boolean;
  first?: number | null;
  after?: string | undefined | null;
  orderBy?: any,
  orderMode?: InputMaybe<OrderingMode>;
  filters?: FilterGroupWithNested | null;
  callback?: (result: Array<T>) => Promise<boolean | void>
  types?: string[]
}

type InternalListEntities = <T extends BasicStoreCommon>
(context: AuthContext, user: AuthUser, entityTypes: Array<string>, args: EntityOptions<T>) => Promise<Array<T>>;

// entities
interface EntityFilters<T extends BasicStoreCommon> extends ListFilter<T> {
  connectionFormat?: boolean;
  elementId?: string | Array<string>;
  fromId?: string | Array<string>;
  fromRole?: string;
  toId?: string | Array<string>;
  toRole?: string;
  fromTypes?: Array<string>;
  toTypes?: Array<string>;
  types?: Array<string>;
  entityTypes?: Array<string>;
  relationshipTypes?: Array<string>;
  elementWithTargetTypes?: Array<string>;
  filters?: FilterGroupWithNested | null;
}

export interface EntityOptions<T extends BasicStoreCommon> extends EntityFilters<T> {
  ids?: Array<string>
  indices?: Array<string>
  noFiltersChecking?: boolean
  includeAuthorities?: boolean | null
}

// relations
interface RelationFilters<T extends BasicStoreCommon> extends ListFilter<T> {
  connectionFormat?: boolean;
  relationFilter?: {
    relation: string;
    id: string;
    relationId: string;
  };
  isTo?: boolean | null;
  elementId?: string | Array<string>;
  fromId?: string | Array<string>;
  fromRole?: string;
  toId?: string | Array<string>;
  toRole?: string;
  fromTypes?: Array<string>,
  toTypes?: Array<string>,
  elementWithTargetTypes?: Array<string>,
  startTimeStart?: string,
  startTimeStop?: string,
  stopTimeStart?: string,
  stopTimeStop?: string,
  firstSeenStart?: string,
  firstSeenStop?: string,
  lastSeenStart?: string,
  lastSeenStop?: string,
  startDate?: string,
  endDate?: string,
  confidences?: Array<string>,
}

export interface RelationOptions<T extends BasicStoreCommon> extends RelationFilters<T> {
  indices?: Array<string>;
  baseData?: boolean;
}

export const buildAggregationFilter = <T extends BasicStoreCommon>(args: RelationFilters<T>) => {
  const { elementId = [], isTo = null } = args;
  const { fromId, fromRole, fromTypes = [] } = args;
  const { toId, toRole, toTypes = [] } = args;
  const filtersContent = [];
  const nestedElement = [];
  const optsElementIds = Array.isArray(elementId) ? elementId : [elementId];
  if (elementId && optsElementIds.length > 0) {
    nestedElement.push({ key: 'internal_id', values: optsElementIds, operator: 'not_eq' });
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

export const buildRelationsFilter = <T extends BasicStoreCommon>(relationshipTypes: string | Array<string>, args: RelationFilters<T>) => {
  const relationsToGet = Array.isArray(relationshipTypes) ? relationshipTypes : [relationshipTypes || 'stix-core-relationship'];
  const {
    relationFilter,
    filters = undefined,
    elementId = [],
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
    startDate,
    endDate,
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
  const nestedElement = [];
  const optsElementIds = Array.isArray(elementId) ? elementId : [elementId];
  if (elementId && optsElementIds.length > 0) {
    nestedElement.push({ key: 'internal_id', values: optsElementIds });
  }
  if (nestedElement.length > 0) {
    filtersFromOptionsContent.push({ key: ['connections'], nested: nestedElement, values: [] });
  }
  const nestedElementTypes = [];
  if (elementWithTargetTypes && elementWithTargetTypes.length > 0) {
    nestedElementTypes.push({ key: 'types', values: elementWithTargetTypes });
    // If elementId is setup, we need to extract the element from the result side
    if (elementId && optsElementIds.length > 0) {
      nestedElementTypes.push({ key: 'internal_id', values: optsElementIds, operator: FilterOperator.NotEq });
    }
  }
  if (nestedElementTypes.length > 0) {
    filtersFromOptionsContent.push({ key: ['connections'], nested: nestedElementTypes, values: [] });
  }
  // endregion
  // region from filtering
  const nestedFrom = [];
  if (fromId) {
    nestedFrom.push({ key: 'internal_id', values: Array.isArray(fromId) ? fromId : [fromId] });
  }
  if (fromTypes && fromTypes.length > 0) {
    nestedFrom.push({ key: 'types', values: fromTypes });
  }
  if (fromRole) {
    nestedFrom.push({ key: 'role', values: [fromRole] });
  } else if (fromId || (fromTypes && fromTypes.length > 0)) {
    nestedFrom.push({ key: 'role', values: ['*_from'], operator: FilterOperator.Wildcard });
  }
  if (nestedFrom.length > 0) {
    filtersFromOptionsContent.push({ key: ['connections'], nested: nestedFrom, values: [] });
  }
  // endregion
  // region to filtering
  const nestedTo = [];
  if (toId) {
    nestedTo.push({ key: 'internal_id', values: Array.isArray(toId) ? toId : [toId] });
  }
  if (toTypes && toTypes.length > 0) {
    nestedTo.push({ key: 'types', values: toTypes });
  }
  if (toRole) {
    nestedTo.push({ key: 'role', values: [toRole] });
  } else if (toId || (toTypes && toTypes.length > 0)) {
    nestedTo.push({ key: 'role', values: ['*_to'], operator: FilterOperator.Wildcard });
  }
  if (nestedTo.length > 0) {
    filtersFromOptionsContent.push({ key: ['connections'], nested: nestedTo, values: [] });
  }
  // endregion
  if (startTimeStart) filtersFromOptionsContent.push({ key: ['start_time'], values: [startTimeStart], operator: FilterOperator.Gt });
  if (startTimeStop) filtersFromOptionsContent.push({ key: ['start_time'], values: [startTimeStop], operator: FilterOperator.Lt });
  if (stopTimeStart) filtersFromOptionsContent.push({ key: ['stop_time'], values: [stopTimeStart], operator: FilterOperator.Gt });
  if (stopTimeStop) filtersFromOptionsContent.push({ key: ['stop_time'], values: [stopTimeStop], operator: FilterOperator.Lt });
  if (firstSeenStart) filtersFromOptionsContent.push({ key: ['first_seen'], values: [firstSeenStart], operator: FilterOperator.Gt });
  if (firstSeenStop) filtersFromOptionsContent.push({ key: ['first_seen'], values: [firstSeenStop], operator: FilterOperator.Lt });
  if (lastSeenStart) filtersFromOptionsContent.push({ key: ['last_seen'], values: [lastSeenStart], operator: FilterOperator.Gt });
  if (lastSeenStop) filtersFromOptionsContent.push({ key: ['last_seen'], values: [lastSeenStop], operator: FilterOperator.Lt });
  if (startDate) filtersFromOptionsContent.push({ key: ['created_at'], values: [startDate], operator: FilterOperator.Gt });
  if (endDate) filtersFromOptionsContent.push({ key: ['created_at'], values: [endDate], operator: FilterOperator.Lt });
  if (confidences && confidences.length > 0) {
    filtersFromOptionsContent.push({ key: ['confidence'], values: confidences });
  }
  // remove options already passed in filters and useless for the next steps
  const cleanedArgs = R.pipe(
    R.dissoc('fromId'),
    R.dissoc('fromRole'),
    R.dissoc('toId'),
    R.dissoc('toRole'),
    R.dissoc('fromTypes'),
    R.dissoc('toTypes'),
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
  let finalFilters = filters;
  if (filtersFromOptionsContent.length > 0) {
    const filtersFromOptions = {
      mode: FilterMode.And,
      filters: filtersFromOptionsContent,
      filterGroups: [],
    };
    finalFilters = filters
      ? {
        mode: filters.mode,
        filters: [],
        filterGroups: [filters, filtersFromOptions],
      }
      : filtersFromOptions;
  }

  return {
    ...cleanedArgs,
    types: relationsToGet,
    filters: finalFilters,
  };
};
export const listRelations = async <T extends StoreProxyRelation>(context: AuthContext, user: AuthUser, type: string | Array<string>,
  args: RelationOptions<T> = {}): Promise<Array<T>> => {
  const { indices = READ_RELATIONSHIPS_INDICES } = args;
  const paginateArgs = buildRelationsFilter(type, args);
  return elPaginate(context, user, indices, paginateArgs);
};
export const listAllRelations = async <T extends StoreProxyRelation>(context: AuthContext, user: AuthUser, type: string | Array<string>,
  args: RelationOptions<T> = {}): Promise<Array<T>> => {
  const { indices = READ_RELATIONSHIPS_INDICES } = args;
  const paginateArgs = buildRelationsFilter(type, args);
  return elList(context, user, indices, paginateArgs);
};

export const buildAggregationRelationFilter = <T extends BasicStoreCommon>(relationshipTypes: string | Array<string>, args: RelationFilters<T>) => {
  const searchOptions = buildRelationsFilter(relationshipTypes, args);
  const aggregationOptions = buildAggregationFilter(args);
  return { ...args, searchOptions, aggregationOptions };
};

// entities
export const buildEntityFilters = <T extends BasicStoreCommon>(args: EntityFilters<T> = {}) => {
  const { types = [], entityTypes = [], relationshipTypes = [] } = args;
  const { elementId, elementWithTargetTypes = [] } = args;
  const { fromId, fromRole, fromTypes = [] } = args;
  const { toId, toRole, toTypes = [] } = args;
  const { filters = null } = args;
  // Config
  const customFiltersContent = [];
  // region element
  const nestedElement = [];
  const optsElementIds = Array.isArray(elementId) ? elementId : [elementId];
  const isElementIdPresent = elementId && optsElementIds.length > 0;
  if (isElementIdPresent) {
    nestedElement.push({ key: 'internal_id', values: optsElementIds as string[] });
  }
  if (nestedElement.length > 0) {
    customFiltersContent.push({ key: ['connections'], nested: nestedElement, values: [] });
  }
  const nestedElementTypes = [];
  if (elementWithTargetTypes && elementWithTargetTypes.length > 0) {
    nestedElementTypes.push({ key: 'types', values: elementWithTargetTypes });
    // If elementId is setup, we need to extract the element from the result side
    if (isElementIdPresent) {
      nestedElementTypes.push({ key: 'internal_id', values: optsElementIds as string[], operator: FilterOperator.NotEq });
    }
  }
  if (nestedElementTypes.length > 0) {
    customFiltersContent.push({ key: ['connections'], nested: nestedElementTypes, values: [] });
  }
  // endregion
  // region from filtering
  const nestedFrom = [];
  if (fromId) {
    nestedFrom.push({ key: 'internal_id', values: Array.isArray(fromId) ? fromId : [fromId] });
  }
  if (fromTypes && fromTypes.length > 0) {
    nestedFrom.push({ key: 'types', values: fromTypes });
  }
  if (fromRole) {
    nestedFrom.push({ key: 'role', values: [fromRole] });
  } else if (fromId || (fromTypes && fromTypes.length > 0)) {
    nestedFrom.push({ key: 'role', values: ['*_from'], operator: FilterOperator.Wildcard });
  }
  if (nestedFrom.length > 0) {
    customFiltersContent.push({ key: ['connections'], nested: nestedFrom, values: [] });
  }
  // endregion
  // region to filtering
  const nestedTo = [];
  if (toId) {
    nestedTo.push({ key: 'internal_id', values: Array.isArray(toId) ? toId : [toId] });
  }
  if (toTypes && toTypes.length > 0) {
    nestedTo.push({ key: 'types', values: toTypes });
  }
  if (toRole) {
    nestedTo.push({ key: 'role', values: [toRole] });
  } else if (toId || (toTypes && toTypes.length > 0)) {
    nestedTo.push({ key: 'role', values: ['*_to'], operator: FilterOperator.Wildcard });
  }
  if (nestedTo.length > 0) {
    customFiltersContent.push({ key: ['connections'], nested: nestedTo, values: [] });
  }
  // endregion
  // Remove options passed in filters
  const builtArgs = R.pipe(
    R.dissoc('fromId'),
    R.dissoc('fromRole'),
    R.dissoc('fromTypes'),
    R.dissoc('toId'),
    R.dissoc('toRole'),
    R.dissoc('toTypes'),
  )(args);
  // Override some special filters
  builtArgs.types = R.uniq([...(types ?? []), ...entityTypes, ...relationshipTypes]);
  let finalFilters = filters;
  if (customFiltersContent.length > 0) {
    const customFilters = {
      mode: FilterMode.And,
      filters: customFiltersContent,
      filterGroups: [],
    };
    finalFilters = filters
      ? {
        mode: filters.mode,
        filters: [],
        filterGroups: [customFilters, filters],
      }
      : customFilters;
  }
  return { ...builtArgs, filters: finalFilters };
};

const entitiesAggregations = [
  { name: CREATOR_FILTER, field: 'creator_id.keyword' },
  { name: ASSIGNEE_FILTER, field: 'rel_object-assignee.internal_id.keyword' },
  { name: PARTICIPANT_FILTER, field: 'rel_object-participant.internal_id.keyword' }
];
export const listAllEntitiesForFilter = async (context: AuthContext, user: AuthUser, filter: string, type: string, args = {}) => {
  const aggregation = entitiesAggregations.find((agg) => agg.name === filter);
  if (!aggregation) {
    throw FunctionalError(`filter ${filter} is not supported as an aggregation.`);
  }
  const aggregationsList = await elAggregationsList(context, user, READ_DATA_INDICES_WITHOUT_INFERRED, [aggregation], args);
  const values = aggregationsList.find((agg) => agg.name === filter)?.values ?? [];
  const nodeElements = values
    .sort((a: { value: string, label: string }, b: { value: string, label: string }) => a.label.localeCompare(b.label))
    .map((val: { value: string, label: string }) => ({ node: { id: val.value, name: val.label, entity_type: type } }));
  return buildPagination(0, null, nodeElements, nodeElements.length);
};

export const listEntities: InternalListEntities = async (context, user, entityTypes, args = {}) => {
  const { indices = READ_ENTITIES_INDICES } = args;
  // TODO Reactivate this test after global migration to typescript
  // if (connectionFormat !== false) {
  //   throw UnsupportedError('List connection require connectionFormat option to false');
  // }
  const paginateArgs = buildEntityFilters({ entityTypes, ...args });
  return elPaginate(context, user, indices, paginateArgs);
};
export const listAllEntities = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, entityTypes: Array<string>,
  args: EntityOptions<T> = {}): Promise<Array<T>> => {
  const { indices = READ_ENTITIES_INDICES } = args;
  const paginateArgs = buildEntityFilters({ entityTypes, ...args });
  return elList(context, user, indices, paginateArgs);
};

export const listEntitiesPaginated = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, entityTypes: Array<string>,
  args: EntityOptions<T> = {}): Promise<StoreEntityConnection<T>> => {
  const { indices = READ_ENTITIES_INDICES, connectionFormat } = args;
  if (connectionFormat === false) {
    throw UnsupportedError('List connection require connectionFormat option to true');
  }
  const paginateArgs = buildEntityFilters({ ...args, entityTypes });
  return elPaginate(context, user, indices, paginateArgs);
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
    type?: string | string[],
    baseData?: boolean,
    toMap?: boolean,
    mapWithAllIds?: boolean,
    baseFields?: string[]
  } & Record<string, string | string[] | boolean>
) => {
  return await elFindByIds(context, user, ids, args) as unknown as T[];
};

export const internalLoadById = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  id: string | undefined,
  opts?: { type?: string, baseData?: boolean },
): Promise<T> => {
  // TODO Remove when all Typescript
  return await elLoadById(context, user, id, opts) as unknown as T;
};

export const storeLoadById = async <T extends BasicStoreCommon>(context: AuthContext, user: AuthUser, id: string, type: string): Promise<T> => {
  if (R.isNil(type) || R.isEmpty(type)) {
    throw FunctionalError('You need to specify a type when loading a element');
  }
  const data = await internalLoadById<T>(context, user, id, { type });
  if (data) {
    const contextData: UserReadActionContextData = {
      id,
      entity_name: extractEntityRepresentativeName(data),
      entity_type: data.entity_type
    };
    if (data.creator_id) {
      contextData.creator_ids = Array.isArray(data.creator_id) ? data.creator_id : [data.creator_id];
    }
    if (data[RELATION_GRANTED_TO]) {
      contextData.granted_refs_ids = data[RELATION_GRANTED_TO];
    }
    if (data[RELATION_OBJECT_MARKING]) {
      contextData.object_marking_refs_ids = data[RELATION_OBJECT_MARKING];
    }
    if (data[RELATION_CREATED_BY]) {
      contextData.created_by_ref_id = data[RELATION_CREATED_BY];
    }
    if (data[RELATION_OBJECT_LABEL]) {
      contextData.labels_ids = data[RELATION_OBJECT_LABEL];
    }
    if (data.entity_type === ENTITY_TYPE_WORKSPACE) {
      contextData.workspace_type = data.type;
    }
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
    throw FunctionalError('You need to specify a type when loading a element');
  }
  const hits = await elFindByIds(context, user, ids, { type, indices: READ_DATA_INDICES });
  return ids.map((id) => (hits as T[]).find((h: T) => h.internal_id === id)) as T[];
};
