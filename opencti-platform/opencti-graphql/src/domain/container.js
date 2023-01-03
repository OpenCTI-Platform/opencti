import * as R from 'ramda';
import { RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { paginateAllThings, listThings, listAllThings } from '../database/middleware';
import { listEntities, listRelations, storeLoadById } from '../database/middleware-loader';
import { buildRefRelationKey, ENTITY_TYPE_CONTAINER, ID_INFERRED, ID_INTERNAL } from '../schema/general';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { buildPagination } from '../database/utils';

const MANUAL_OBJECT = 'manual';
const INFERRED_OBJECT = 'inferred';

export const findById = async (context, user, containerId) => {
  return storeLoadById(context, user, containerId, ENTITY_TYPE_CONTAINER);
};

export const findAll = async (context, user, args) => {
  const hasTypesArgs = args.types && args.types.length > 0;
  const types = hasTypesArgs ? args.types.filter((type) => isStixDomainObjectContainer(type)) : [ENTITY_TYPE_CONTAINER];
  return listEntities(context, user, types, args);
};

export const objects = async (context, user, containerId, args) => {
  const key = buildRefRelationKey(RELATION_OBJECT, '*');
  const types = args.types ? args.type
    : ['Stix-Core-Object', 'stix-core-relationship', 'stix-sighting-relationship', 'stix-cyber-observable-relationship'];
  const filters = [{ key, values: [containerId], operator: 'wildcard' }, ...(args.filters || [])];
  const data = args.all ? await paginateAllThings(context, user, types, R.assoc('filters', filters, args))
    : await listThings(context, user, types, R.assoc('filters', filters, args));
  // Container objects can be manual and/or inferred
  // This type must be specified to inform the UI what's need to be done.
  for (let index = 0; index < data.edges.length; index += 1) {
    const edge = data.edges[index];
    const relIdObjects = edge.node[buildRefRelationKey(RELATION_OBJECT, ID_INTERNAL)] ?? [];
    const relInferredObjects = edge.node[buildRefRelationKey(RELATION_OBJECT, ID_INFERRED)] ?? [];
    const refTypes = [];
    if (relIdObjects.includes(containerId)) {
      refTypes.push(MANUAL_OBJECT);
    }
    if (relInferredObjects.includes(containerId)) {
      refTypes.push(INFERRED_OBJECT);
    }
    edge.types = refTypes;
  }
  return data;
};

export const relatedContainers = async (context, user, containerId, args) => {
  const key = buildRefRelationKey(RELATION_OBJECT);
  const types = args.viaTypes ? args.viaTypes : ['Stix-Core-Object', 'stix-core-relationship'];
  const filters = [{ key, values: [containerId] }];
  const elements = await listAllThings(context, user, types, { filters });
  if (elements.length === 0) {
    return buildPagination(0, null, [], 0);
  }
  const elementsIds = elements.map((element) => element.id).slice(0, 800);
  const queryFilters = [...(args.filters || []), { key: buildRefRelationKey(RELATION_OBJECT), values: elementsIds }];
  const queryArgs = { ...args, filters: queryFilters };
  return findAll(context, user, queryArgs);
};

export const containersObjectsOfObject = async (context, user, { id, types, filters = [], search = null }) => {
  const queryFilters = [...filters, { key: buildRefRelationKey(RELATION_OBJECT), values: [id] }];
  const containerConnection = await findAll(context, user, { first: 1000, search, filters: queryFilters });
  const listRelationPromises = containerConnection.edges.map((n) => listRelations(context, user, RELATION_OBJECT, {
    first: 1000,
    fromId: n.node.id,
    toTypes: types,
  }));
  const containersObjectsRelationshipsEdges = await Promise.all(listRelationPromises);
  const containersObjectsRelationships = R.flatten(R.map((n) => n.edges, containersObjectsRelationshipsEdges));
  const containersObjects = await Promise.all(containersObjectsRelationships.map((n) => storeLoadById(context, user, n.node.toId, n.node.toType)));
  const containersObjectsResult = R.uniqBy(R.path(['node', 'id']), [
    ...containerConnection.edges,
    ...containersObjectsRelationships,
    ...R.map((n) => ({ node: n }), containersObjects),
  ]);
  return buildPagination(0, null, containersObjectsResult, containersObjectsResult.length);
};
