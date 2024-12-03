import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixRefRelationship';
import { listAllThings, timeSeriesEntities } from '../database/middleware';
import { internalFindByIds, internalLoadById, listAllEntities, listEntities, listEntitiesThroughRelationsPaginated, storeLoadById } from '../database/middleware-loader';
import {
  ABSTRACT_BASIC_RELATIONSHIP,
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_REF_RELATIONSHIP,
  ABSTRACT_STIX_RELATIONSHIP,
  buildRefRelationKey,
  ENTITY_TYPE_CONTAINER
} from '../schema/general';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { buildPagination, READ_ENTITIES_INDICES, READ_INDEX_STIX_DOMAIN_OBJECTS, READ_RELATIONSHIPS_INDICES } from '../database/utils';
import { now } from '../utils/format';
import { elCount, elFindByIds, ES_DEFAULT_PAGINATION, MAX_RELATED_CONTAINER_OBJECT_RESOLUTION, MAX_RELATED_CONTAINER_RESOLUTION } from '../database/engine';
import { findById as findInvestigationById } from '../modules/workspace/workspace-domain';
import { stixCoreObjectAddRelations } from './stixCoreObject';
import { editAuthorizedMembers } from '../utils/authorizedMembers';
import { addFilter } from '../utils/filtering/filtering-utils';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { isFeatureEnabled } from '../config/conf';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../modules/case/feedback/feedback-types';
import { paginatedForPathWithEnrichment } from '../modules/internal/document/document-domain';
import { isEnterpriseEdition } from '../utils/ee';
import { ENTITY_TYPE_FINTEL_TEMPLATE } from '../modules/fintelTemplate/fintelTemplate-types';

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
      const currentPagination = await listEntitiesThroughRelationsPaginated(context, user, containerId, RELATION_OBJECT, types, false, paginateOpts);
      const noMoreElements = (currentPagination.baseCount ?? 0) === 0 || currentPagination.baseCount < paginateOpts.first;
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
  return listEntitiesThroughRelationsPaginated(context, user, containerId, RELATION_OBJECT, types, false, baseOpts);
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
  let objectIds = [];
  let hasMoreThanMaxObject = false;
  let loadedReportsCount = 0;
  for (let i = 0; i < containers.length; i += 1) {
    const currentContainer = containers[0];
    const currentContainerObjectIds = currentContainer[buildRefRelationKey(RELATION_OBJECT)].flat();
    objectIds = R.uniq(objectIds.concat(...currentContainerObjectIds));
    loadedReportsCount += 1;
    if (objectIds.length > MAX_RELATED_CONTAINER_OBJECT_RESOLUTION) {
      hasMoreThanMaxObject = true;
      break;
    }
  }
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
  const limit = hasMoreThanMaxObject ? resolvedObjects.length : 0;
  const globalCount = hasMoreThanMaxObject ? loadedReportsCount : resolvedObjects.length;
  return buildPagination(limit, null, resolvedObjects.map((r) => ({ node: r })), globalCount);
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

export const containerEditAuthorizedMembers = async (context, user, entityId, input) => {
  const args = {
    entityId,
    input,
    requiredCapabilities: ['KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS'],
    entityType: ENTITY_TYPE_CONTAINER,
    busTopicKey: ABSTRACT_STIX_CORE_OBJECT,
  };
  const entity = await findById(context, user, entityId);
  if (!entity) {
    throw FunctionalError('Cant find element to update', { entityId });
  }
  if (entity.entity_type !== ENTITY_TYPE_CONTAINER_FEEDBACK && !isFeatureEnabled('CONTAINERS_AUTHORIZED_MEMBERS')) {
    throw UnsupportedError('This feature is disabled');
  }
  return editAuthorizedMembers(context, user, args);
};

export const getFilesFromTemplate = async (context, user, container, args) => {
  const isEE = await isEnterpriseEdition(context);
  const isFileFromTemplateEnabled = isFeatureEnabled('FILE_FROM_TEMPLATE');
  if (!isEE || !isFileFromTemplateEnabled) {
    return null;
  }
  const { first, prefixMimeType } = args;
  const opts = { first, prefixMimeTypes: prefixMimeType ? [prefixMimeType] : null, entity_id: container.id, entity_type: container.entity_type };
  return paginatedForPathWithEnrichment(context, user, `fromTemplate/${container.entity_type}/${container.id}`, container.id, opts);
};

export const getFintelTemplates = async (context, user, container) => {
  const isEE = await isEnterpriseEdition(context);
  const isFileFromTemplateEnabled = isFeatureEnabled('FILE_FROM_TEMPLATE');
  if (!isEE || !isFileFromTemplateEnabled) {
    return null;
  }
  const nowDate = new Date().getTime();
  const filters = {
    mode: 'and',
    filters: [
      {
        key: 'settings_types',
        values: [container.entity_type],
        operator: 'eq',
      },
      {
        key: 'start_date',
        values: [nowDate],
        operator: 'lte',
      }
    ],
    filterGroups: [],
  };
  return listAllEntities(context, user, [ENTITY_TYPE_FINTEL_TEMPLATE], { filters });
};
