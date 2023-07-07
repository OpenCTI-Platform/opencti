import * as R from 'ramda';
import {
  buildPagination,
  offsetToCursor,
  READ_DATA_INDICES,
  READ_ENTITIES_INDICES,
  READ_RELATIONSHIPS_INDICES,
  extractEntityRepresentative,
} from './utils';
import { elAggregationsList, elCount, elFindByIds, elLoadById, elPaginate } from './engine';
import { buildRefRelationKey } from '../schema/general';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreCommon, BasicStoreEntity, BasicStoreObject, StoreEntityConnection, StoreProxyRelation } from '../types/store';
import { FunctionalError, UnsupportedError } from '../config/errors';
import type { FilterMode, InputMaybe, OrderingMode } from '../generated/graphql';
import { ASSIGNEE_FILTER, CREATOR_FILTER, PARTICIPANT_FILTER } from '../utils/filtering';
import { publishUserAction } from '../listener/UserActionListener';

const MAX_SEARCH_SIZE = 5000;

export interface Filter {
  key: any;
  operator?: string | null;
  filterMode?: InputMaybe<FilterMode>;
  values?: any;
  nested?: Array<{
    key: string;
    values?: Array<unknown> | null;
    operator?: string;
  }>;
}

export interface ListFilter<T extends BasicStoreCommon> {
  indices?: Array<string>;
  search?: InputMaybe<string> | string | undefined;
  useWildcardPrefix?: boolean;
  useWildcardSuffix?: boolean;
  first?: number | null;
  infinite?: boolean;
  after?: string | undefined | null;
  orderBy?: any,
  orderMode?: InputMaybe<OrderingMode>;
  filters?: Array<Filter> | null;
  filterMode?: FilterMode | undefined | null;
  callback?: (result: Array<T>) => Promise<boolean | void>
}

type InternalListEntities = <T extends BasicStoreCommon>(context: AuthContext, user: AuthUser, entityTypes: Array<string>, args: EntityOptions<T>) => Promise<Array<T>>;

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
}

export interface EntityOptions<T extends BasicStoreCommon> extends EntityFilters<T> {
  ids?: Array<string>;
  indices?: Array<string>;
}

export const elList = async <T extends BasicStoreCommon>(context: AuthContext, user: AuthUser, indices: Array<string>, options: ListFilter<T> = {}): Promise<Array<T>> => {
  const { first = MAX_SEARCH_SIZE, infinite = false } = options;
  let hasNextPage = true;
  let continueProcess = true;
  let searchAfter = options.after;
  const listing: Array<T> = [];
  const publish = async (elements: Array<T>) => {
    const { callback } = options;
    if (callback) {
      const callbackResult = await callback(elements);
      continueProcess = callbackResult || callbackResult === undefined;
    } else {
      listing.push(...elements);
    }
  };
  while (continueProcess && hasNextPage) {
    // Force options to prevent connection format and manage search after
    const opts = { ...options, first, after: searchAfter, connectionFormat: false };
    const elements = await elPaginate(context, user, indices, opts);
    if (!infinite && (elements.length === 0 || elements.length < (first ?? MAX_SEARCH_SIZE))) {
      if (elements.length > 0) {
        await publish(elements);
      }
      hasNextPage = false;
    } else if (elements.length > 0) {
      const { sort } = elements[elements.length - 1];
      searchAfter = offsetToCursor(sort);
      await publish(elements);
    }
  }
  return listing;
};

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
  startTimeStart?: Date,
  startTimeStop?: Date,
  stopTimeStart?: Date,
  stopTimeStop?: Date,
  firstSeenStart?: Date,
  firstSeenStop?: Date,
  lastSeenStart?: Date,
  lastSeenStop?: Date,
  startDate?: Date,
  endDate?: Date,
  confidences?: Array<number>,
}

export interface RelationOptions<T extends BasicStoreCommon> extends RelationFilters<T> {
  indices?: Array<string>;
}

export const buildAggregationFilter = <T extends BasicStoreCommon>(args: RelationFilters<T>) => {
  const { elementId = [], isTo = null } = args;
  const { fromId, fromRole, fromTypes = [] } = args;
  const { toId, toRole, toTypes = [] } = args;
  const filters = [];
  const nestedElement = [];
  const optsElementIds = Array.isArray(elementId) ? elementId : [elementId];
  if (elementId && optsElementIds.length > 0) {
    nestedElement.push({ key: 'internal_id', values: optsElementIds, operator: 'not_eq' });
    filters.push({ key: 'connections', nested: nestedElement });
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
    filters.push({ key: 'connections', nested: nestedFrom });
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
    filters.push({ key: 'connections', nested: nestedTo });
  }
  return { filters };
};

export const buildRelationsFilter = <T extends BasicStoreCommon>(relationshipTypes: string | Array<string>, args: RelationFilters<T>) => {
  const relationsToGet = Array.isArray(relationshipTypes) ? relationshipTypes : [relationshipTypes || 'stix-core-relationship'];
  const { relationFilter } = args;
  const {
    filters = [],
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
  const finalFilters = filters ?? [];
  if (relationFilter) {
    const { relation, id, relationId } = relationFilter;
    finalFilters.push({ key: buildRefRelationKey(relation), values: [id] });
    if (relationId) {
      finalFilters.push({ key: 'internal_id', values: [relationId] });
    }
  }
  // region element filtering
  const nestedElement = [];
  const optsElementIds = Array.isArray(elementId) ? elementId : [elementId];
  if (elementId && optsElementIds.length > 0) {
    nestedElement.push({ key: 'internal_id', values: optsElementIds });
  }
  if (nestedElement.length > 0) {
    finalFilters.push({ key: 'connections', nested: nestedElement });
  }
  const nestedElementTypes = [];
  if (elementWithTargetTypes && elementWithTargetTypes.length > 0) {
    nestedElementTypes.push({ key: 'types', values: elementWithTargetTypes });
  }
  if (nestedElementTypes.length > 0) {
    finalFilters.push({ key: 'connections', nested: nestedElementTypes });
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
    nestedFrom.push({ key: 'role', values: ['*_from'], operator: 'wildcard' });
  }
  if (nestedFrom.length > 0) {
    finalFilters.push({ key: 'connections', nested: nestedFrom });
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
    nestedTo.push({ key: 'role', values: ['*_to'], operator: 'wildcard' });
  }
  if (nestedTo.length > 0) {
    finalFilters.push({ key: 'connections', nested: nestedTo });
  }
  // endregion
  if (startTimeStart) finalFilters.push({ key: 'start_time', values: [startTimeStart], operator: 'gt' });
  if (startTimeStop) finalFilters.push({ key: 'start_time', values: [startTimeStop], operator: 'lt' });
  if (stopTimeStart) finalFilters.push({ key: 'stop_time', values: [stopTimeStart], operator: 'gt' });
  if (stopTimeStop) finalFilters.push({ key: 'stop_time', values: [stopTimeStop], operator: 'lt' });
  if (firstSeenStart) finalFilters.push({ key: 'first_seen', values: [firstSeenStart], operator: 'gt' });
  if (firstSeenStop) finalFilters.push({ key: 'first_seen', values: [firstSeenStop], operator: 'lt' });
  if (lastSeenStart) finalFilters.push({ key: 'last_seen', values: [lastSeenStart], operator: 'gt' });
  if (lastSeenStop) finalFilters.push({ key: 'last_seen', values: [lastSeenStop], operator: 'lt' });
  if (startDate) finalFilters.push({ key: 'created_at', values: [startDate], operator: 'gt' });
  if (endDate) finalFilters.push({ key: 'created_at', values: [endDate], operator: 'lt' });
  if (confidences && confidences.length > 0) {
    finalFilters.push({ key: 'confidence', values: confidences });
  }
  return R.pipe(R.assoc('types', relationsToGet), R.assoc('filters', finalFilters))(args);
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
}

export const buildEntityFilters = <T extends BasicStoreCommon>(args: EntityFilters<T> = {}) => {
  const builtFilters = { ...args };
  const { types = [], entityTypes = [], relationshipTypes = [] } = args;
  const { elementId, elementWithTargetTypes = [] } = args;
  const { fromId, fromRole, fromTypes = [] } = args;
  const { toId, toRole, toTypes = [] } = args;
  const { filters = [] } = args;
  // Config
  const customFilters = [...(filters ?? [])];
  // region element
  const nestedElement = [];
  if (elementId) {
    nestedElement.push({ key: 'internal_id', values: Array.isArray(elementId) ? elementId : [elementId] });
  }
  if (nestedElement.length > 0) {
    customFilters.push({ key: 'connections', nested: nestedElement });
  }
  const nestedElementTypes = [];
  if (elementWithTargetTypes && elementWithTargetTypes.length > 0) {
    nestedElementTypes.push({ key: 'types', values: elementWithTargetTypes });
  }
  if (nestedElementTypes.length > 0) {
    customFilters.push({ key: 'connections', nested: nestedElementTypes });
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
    nestedFrom.push({ key: 'role', values: ['*_from'], operator: 'wildcard' });
  }
  if (nestedFrom.length > 0) {
    customFilters.push({ key: 'connections', nested: nestedFrom });
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
    nestedTo.push({ key: 'role', values: ['*_to'], operator: 'wildcard' });
  }
  if (nestedTo.length > 0) {
    customFilters.push({ key: 'connections', nested: nestedTo });
  }
  // endregion
  // Override some special filters
  builtFilters.types = R.uniq([...(types ?? []), ...entityTypes, ...relationshipTypes]);
  builtFilters.filters = customFilters;
  return builtFilters;
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
  const aggregationsList = await elAggregationsList(context, user, READ_ENTITIES_INDICES, [aggregation], args);
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
  const paginateArgs = buildEntityFilters({ entityTypes, ...args });
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
  args?: { type?: string | string[], baseData?: boolean, baseFields?: string[] } & Record<string, string | string[] | boolean>
) => {
  return await elFindByIds(context, user, ids, args) as unknown as T[];
};

export const internalLoadById = async <T extends BasicStoreObject>(
  context: AuthContext,
  user: AuthUser,
  id: string | undefined,
  opts?: { type?: string, baseData?: boolean },
): Promise<T> => {
  // TODO Remove when all Typescript
  return await elLoadById(context, user, id, opts) as unknown as T;
};

export const storeLoadById = async <T extends BasicStoreObject>(context: AuthContext, user: AuthUser, id: string, type: string): Promise<T> => {
  if (R.isNil(type) || R.isEmpty(type)) {
    throw FunctionalError('You need to specify a type when loading a element');
  }
  const data = await internalLoadById<T>(context, user, id, { type });
  if (data) {
    await publishUserAction({
      user,
      event_type: 'read',
      event_access: 'extended',
      event_scope: 'read',
      context_data: {
        id,
        entity_name: extractEntityRepresentative(data),
        entity_type: data.entity_type
      }
    });
  }
  return data;
};

export const storeLoadByIds = async <T extends BasicStoreObject>(context: AuthContext, user: AuthUser, ids: string[], type: string): Promise<T[]> => {
  if (R.isNil(type) || R.isEmpty(type)) {
    throw FunctionalError('You need to specify a type when loading a element');
  }
  const hits = await elFindByIds(context, user, ids, { type, indices: READ_DATA_INDICES });
  return ids.map((id) => (hits as T[]).find((h: T) => h.internal_id === id)) as T[];
};
