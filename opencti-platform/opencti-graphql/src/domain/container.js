import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import { RELATION_OBJECT } from '../schema/stixRefRelationship';
import { listAllThings } from '../database/middleware';
import { internalFindByIds, listEntities, listEntitiesThroughRelationsPaginated, storeLoadById } from '../database/middleware-loader';
import { ABSTRACT_BASIC_RELATIONSHIP, ABSTRACT_STIX_REF_RELATIONSHIP, ABSTRACT_STIX_RELATIONSHIP, buildRefRelationKey, ENTITY_TYPE_CONTAINER } from '../schema/general';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { buildPagination, READ_ENTITIES_INDICES, READ_INDEX_STIX_DOMAIN_OBJECTS, READ_RELATIONSHIPS_INDICES } from '../database/utils';
import { now } from '../utils/format';
import { elFindByIds, elCount, ES_MAX_PAGINATION } from '../database/engine';
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
  const baseOpts = { ...args, first: ES_MAX_PAGINATION, indices: [...READ_ENTITIES_INDICES, ...READ_RELATIONSHIPS_INDICES] };
  if (args.all) {
    // TODO Should be handled by the frontend to split the load
    // As we currently handle it in the back, just do a standard iteration
    // Then return the complete result set
    let hasNextPage = true;
    let searchAfter = args.after;
    const paginatedElements = {};
    while (hasNextPage) {
      // Force options to prevent connection format and manage search after
      const paginateOpts = { ...baseOpts, after: searchAfter };
      const currentPagination = await listEntitiesThroughRelationsPaginated(context, user, containerId, RELATION_OBJECT, types, false, paginateOpts);
      const noMoreElements = currentPagination.edges.length === 0 || currentPagination.edges.length < ES_MAX_PAGINATION;
      if (noMoreElements) {
        hasNextPage = false;
        paginatedElements.pageInfo = currentPagination.pageInfo;
        paginatedElements.edges = [...(paginatedElements.edges ?? []), ...currentPagination.edges];
        return paginatedElements;
      }
      if (currentPagination.edges.length > 0) {
        const { cursor } = currentPagination.edges[currentPagination.edges.length - 1];
        searchAfter = cursor;
        paginatedElements.pageInfo = currentPagination.pageInfo;
        paginatedElements.edges = [...(paginatedElements.edges ?? []), ...currentPagination.edges];
      }
    }
  }
  return listEntitiesThroughRelationsPaginated(context, user, containerId, RELATION_OBJECT, types, false, baseOpts);
};

export const relatedContainers = async (context, user, containerId, args) => {
  const key = buildRefRelationKey(RELATION_OBJECT);
  const types = args.viaTypes ? args.viaTypes : ['Stix-Core-Object', 'stix-core-relationship'];
  const filters = {
    mode: 'and',
    filters: [{ key, values: [containerId] }],
    filterGroups: [],
  };
  const elements = await listAllThings(context, user, types, { filters });
  if (elements.length === 0) {
    return buildPagination(0, null, [], 0);
  }
  const elementsIds = elements.map((element) => element.id).slice(0, 800);
  const queryFilters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT), elementsIds);
  const queryArgs = { ...args, filters: queryFilters };
  return findAll(context, user, queryArgs);
};

export const containersObjectsOfObject = async (context, user, { id, types, filters = null, search = null }) => {
  const queryFilters = addFilter(filters, buildRefRelationKey(RELATION_OBJECT), id);
  const containers = await findAll(context, user, { types: [ENTITY_TYPE_CONTAINER], first: 1000, search, filters: queryFilters, connectionFormat: false });
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
          entity_type: c.entity_type,
          parent_types: c.parent_types,
          relationship_type: c.parent_types.includes(ABSTRACT_BASIC_RELATIONSHIP) ? c.entity_type : null
        },
        to: {
          id: toId,
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
  return await stixCoreObjectAddRelations(context, user, containerId, containerInput);
};
