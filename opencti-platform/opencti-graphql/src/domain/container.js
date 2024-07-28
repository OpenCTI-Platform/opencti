import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixRefRelationship';
import { listAllThings, timeSeriesEntities } from '../database/middleware';
import { internalFindByIds, internalLoadById, listEntities, listEntitiesThroughRelationsPaginated, storeLoadById } from '../database/middleware-loader';
import { ABSTRACT_BASIC_RELATIONSHIP, ABSTRACT_STIX_REF_RELATIONSHIP, ABSTRACT_STIX_RELATIONSHIP, buildRefRelationKey, ENTITY_TYPE_CONTAINER } from '../schema/general';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { buildPagination, READ_ENTITIES_INDICES, READ_INDEX_STIX_DOMAIN_OBJECTS, READ_RELATIONSHIPS_INDICES } from '../database/utils';
import { now } from '../utils/format';
import { elCount, elFindByIds, ES_DEFAULT_PAGINATION, MAX_RELATED_CONTAINER_RESOLUTION } from '../database/engine';
import { findById as findInvestigationById } from '../modules/workspace/workspace-domain';
import { stixCoreObjectAddRelations } from './stixCoreObject';
import { addFilter } from '../utils/filtering/filtering-utils';

export const findById = async (context, user, containerId) => {
  return storeLoadById(context, user, containerId, ENTITY_TYPE_CONTAINER);
};

export const findAll = async (context, user, args) => {
  const hasTypesArgs = args.types && args.types.length > 0;
  const types = hasTypesArgs ? args.types.filter((type) => isStixDomainObjectContainer(type)) : [ENTITY_TYPE_CONTAINER];
  return listEntities(context, user, types, args);
};

export const numberOfContainersForObject = (context, user, args) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  return {
    count: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...args, filters, types: [ENTITY_TYPE_CONTAINER] },
    ),
    total: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...R.dissoc('endDate', args), filters, types: [ENTITY_TYPE_CONTAINER] },
    ),
  };
};

export const objects = async (context, user, containerId, args) => {
  const types = args.types ? args.types : ['Stix-Core-Object', 'stix-relationship'];
  const baseOpts = { ...args, indices: [...READ_ENTITIES_INDICES, ...READ_RELATIONSHIPS_INDICES] };
  if (args.all) {
    // TODO Should be handled by the frontend to split the load
    // As we currently handle it in the back, just do a standard iteration
    // Then return the complete result set
    let hasNextPage = true;
    let searchAfter = args.after;
    const paginatedElements = {};
    while (hasNextPage) {
      // Force options to prevent connection format and manage search after
      const paginateOpts = { ...baseOpts, first: args.first ?? ES_DEFAULT_PAGINATION, after: searchAfter };
      const currentPagination = await listEntitiesThroughRelationsPaginated(context, user, containerId, RELATION_OBJECT, types, false, false, paginateOpts);
      const noMoreElements = currentPagination.edges.length === 0 || currentPagination.edges.length < paginateOpts.first;
      if (noMoreElements) {
        hasNextPage = false;
        paginatedElements.pageInfo = currentPagination.pageInfo;
        paginatedElements.edges = [...(paginatedElements.edges ?? []), ...currentPagination.edges];
      } else if (currentPagination.edges.length > 0) {
        const { cursor } = currentPagination.edges[currentPagination.edges.length - 1];
        searchAfter = cursor;
        paginatedElements.pageInfo = currentPagination.pageInfo;
        paginatedElements.edges = [...(paginatedElements.edges ?? []), ...currentPagination.edges];
      }
    }
    return paginatedElements;
  }
  return listEntitiesThroughRelationsPaginated(context, user, containerId, RELATION_OBJECT, types, false, false, baseOpts);
};

export const containersNumber = (context, user, args) => {
  return {
    count: elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { ...args, types: [ENTITY_TYPE_CONTAINER] }),
    total: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...R.dissoc('endDate', args), types: [ENTITY_TYPE_CONTAINER] }
    ),
  };
};

export const containersTimeSeriesByEntity = (context, user, args) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER], { ...args, filters });
};

export const containersTimeSeriesByAuthor = async (context, user, args) => {
  const { authorId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_CREATED_BY, '*'), authorId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER], { ...args, filters });
};

export const containersNumberByEntity = (context, user, args) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  return {
    count: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...args, filters, types: [ENTITY_TYPE_CONTAINER] },
    ),
    total: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...R.dissoc('endDate', args), filters, types: [ENTITY_TYPE_CONTAINER] },
    ),
  };
};

export const containersNumberByAuthor = (context, user, args) => {
  const { authorId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_CREATED_BY, '*'), authorId);
  return {
    count: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...args, filters, types: [ENTITY_TYPE_CONTAINER] },
    ),
    total: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...R.dissoc('endDate', args), filters, types: [ENTITY_TYPE_CONTAINER] },
    ),
  };
};

// List first 1000 objects of this container
// Then find the containers that contains also the resolved objects
export const relatedContainers = async (context, user, containerId, args) => {
  const key = buildRefRelationKey(RELATION_OBJECT);
  const types = args.viaTypes ? args.viaTypes : ['Stix-Core-Object', 'stix-core-relationship'];
  const filters = {
    mode: 'and',
    filters: [{ key, values: [containerId] }],
    filterGroups: [],
  };
  const elements = await listAllThings(context, user, types, { filters, maxSize: MAX_RELATED_CONTAINER_RESOLUTION, baseData: true });
  if (elements.length === 0) {
    return buildPagination(0, null, [], 0);
  }
  const elementsIds = elements.map((element) => element.id);
  const queryFilters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT), elementsIds);
  const queryArgs = { ...args, filters: queryFilters };
  return findAll(context, user, queryArgs);
};

// Starting an object, get 1000 containers that have this object
// Then get all objects for all of this containers
export const containersObjectsOfObject = async (context, user, { id, types, filters = null, search = null }) => {
  const element = await internalLoadById(context, user, id);
  const queryFilters = addFilter(filters, buildRefRelationKey(RELATION_OBJECT), element.internal_id);
  const containers = await listAllThings(context, user, [ENTITY_TYPE_CONTAINER], { filters: queryFilters, maxSize: MAX_RELATED_CONTAINER_RESOLUTION, search });
  const objectIds = R.uniq(containers.map((n) => n[buildRefRelationKey(RELATION_OBJECT)]).flat());
  const resolvedObjectsMap = await internalFindByIds(context, user, objectIds, { type: types, toMap: true });
  const resolvedObjects = Object.values(resolvedObjectsMap);
  resolvedObjects.push(
    ...containers,
    ...(containers.map((c) => c[buildRefRelationKey(RELATION_OBJECT)].filter((toId) => resolvedObjectsMap[toId]).map((toId) => (
      {
        id: uuidv4(),
        created_at: now(),
        updated_at: now(),
        parent_types: [ABSTRACT_BASIC_RELATIONSHIP, ABSTRACT_STIX_RELATIONSHIP, ABSTRACT_STIX_REF_RELATIONSHIP],
        entity_type: RELATION_OBJECT,
        relationship_type: RELATION_OBJECT,
        from: {
          id: c.id,
          standard_id: c.standard_id,
          entity_type: c.entity_type,
          parent_types: c.parent_types,
          relationship_type: c.parent_types.includes(ABSTRACT_BASIC_RELATIONSHIP) ? c.entity_type : null
        },
        to: {
          id: toId,
          standard_id: resolvedObjectsMap[toId].standard_id,
          entity_type: resolvedObjectsMap[toId].entity_type,
          parent_types: resolvedObjectsMap[toId].parent_types,
          relationship_type: resolvedObjectsMap[toId].parent_types.includes(ABSTRACT_BASIC_RELATIONSHIP) ? resolvedObjectsMap[toId].entity_type : null
        }
      }
    ))).flat())
  );
  return buildPagination(0, null, resolvedObjects.map((r) => ({ node: r })), resolvedObjects.length);
};

export const filterUnwantedEntitiesOut = async ({ context, user, ids }) => {
  const filteredOutInvestigatedIds = [];
  const entities = await elFindByIds(context, user, ids);
  entities?.forEach((entity) => {
    if (!['Task', 'Note'].includes(entity.entity_type)) {
      filteredOutInvestigatedIds.push(entity.id);
    }
  });
  return filteredOutInvestigatedIds;
};

export const knowledgeAddFromInvestigation = async (context, user, { containerId, workspaceId }) => {
  const investigation = await findInvestigationById(context, user, workspaceId);
  const ids = investigation.investigated_entities_ids?.filter((id) => id !== containerId);
  const toIds = await filterUnwantedEntitiesOut({ context, user, ids });
  const containerInput = { toIds, relationship_type: 'object' };
  const patched = await stixCoreObjectAddRelations(context, user, containerId, containerInput);
  // Reload on this is mandatory to get the rel_ from the element for accurate counting
  return internalLoadById(context, user, patched.internal_id, patched.entity_type);
};
