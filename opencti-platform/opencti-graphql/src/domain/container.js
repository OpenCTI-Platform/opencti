import * as R from 'ramda';
import { RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { paginateAllThings, listThings, storeLoadById, listAllThings } from '../database/middleware';
import { listEntities, listRelations } from '../database/middleware-loader';
import { buildRefRelationKey, ENTITY_TYPE_CONTAINER } from '../schema/general';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { buildPagination } from '../database/utils';

export const findById = async (user, containerId) => {
  return storeLoadById(user, containerId, ENTITY_TYPE_CONTAINER);
};

export const findAll = async (user, args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = R.filter((type) => isStixDomainObjectContainer(type), args.types);
  }
  if (types.length === 0) {
    types.push(ENTITY_TYPE_CONTAINER);
  }
  return listEntities(user, types, args);
};

// Entities tab
export const objects = async (user, containerId, args) => {
  const key = buildRefRelationKey(RELATION_OBJECT);
  let types = ['Stix-Core-Object', 'stix-core-relationship', 'stix-sighting-relationship', 'stix-cyber-observable-relationship'];
  if (args.types) {
    types = args.types;
  }
  const filters = [{ key, values: [containerId] }, ...(args.filters || [])];
  if (args.all) {
    return paginateAllThings(user, types, R.assoc('filters', filters, args));
  }
  return listThings(user, types, R.assoc('filters', filters, args));
};
export const relatedContainers = async (user, containerId, args) => {
  const key = buildRefRelationKey(RELATION_OBJECT);
  let types = ['Stix-Core-Object', 'stix-core-relationship'];
  if (args.viaTypes) {
    types = args.viaTypes;
  }
  const filters = [{ key, values: [containerId] }];
  const elements = await listAllThings(user, types, { filters });
  if (elements.length === 0) {
    return buildPagination(0, null, [], 0);
  }
  const elementsIds = elements.map((element) => element.id).slice(0, 800);
  const queryArgs = {
    ...args,
    filters: [...(args.filters || []), { key: buildRefRelationKey(RELATION_OBJECT), values: elementsIds }],
  };
  return findAll(user, queryArgs);
};
// endregion

export const containersObjectsOfObject = async (user, { id, types, filters = [], search = null }) => {
  const containers = await findAll(user, {
    first: 1000,
    search,
    filters: [...filters, { key: buildRefRelationKey(RELATION_OBJECT), values: [id] }],
  });
  const containersObjectsRelationshipsEdges = await Promise.all(
    R.map(
      (n) => listRelations(user, RELATION_OBJECT, {
        first: 1000,
        fromId: n.node.id,
        toTypes: types,
      }),
      containers.edges
    )
  );
  const containersObjectsRelationships = R.flatten(R.map((n) => n.edges, containersObjectsRelationshipsEdges));
  const containersObjects = await Promise.all(
    R.map((n) => storeLoadById(user, n.node.toId, n.node.toType), containersObjectsRelationships)
  );
  const containersObjectsResult = R.uniqBy(R.path(['node', 'id']), [
    ...containers.edges,
    ...containersObjectsRelationships,
    ...R.map((n) => ({ node: n }), containersObjects),
  ]);
  return buildPagination(0, null, containersObjectsResult, containersObjectsResult.length);
};
