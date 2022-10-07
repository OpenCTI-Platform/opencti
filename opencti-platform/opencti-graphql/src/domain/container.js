import * as R from 'ramda';
import { RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { paginateAllThings, listThings, storeLoadById, listAllThings } from '../database/middleware';
import { listEntities, listRelations } from '../database/middleware-loader';
import { buildRefRelationKey, ENTITY_TYPE_CONTAINER, ID_INFERRED, ID_INTERNAL } from '../schema/general';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { buildPagination } from '../database/utils';

export const findById = async (context, user, containerId) => {
  return storeLoadById(context, user, containerId, ENTITY_TYPE_CONTAINER);
};

export const findAll = async (context, user, args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = R.filter((type) => isStixDomainObjectContainer(type), args.types);
  }
  if (types.length === 0) {
    types.push(ENTITY_TYPE_CONTAINER);
  }
  return listEntities(context, user, types, args);
};

// Entities tab
export const objects = async (context, user, containerId, args) => {
  const key = buildRefRelationKey(RELATION_OBJECT, '*');
  let types = ['Stix-Core-Object', 'stix-core-relationship', 'stix-sighting-relationship', 'stix-cyber-observable-relationship'];
  if (args.types) {
    types = args.types;
  }
  const filters = [{ key, values: [containerId], operator: 'wildcard' }, ...(args.filters || [])];
  let data;
  if (args.all) {
    data = await paginateAllThings(context, user, types, R.assoc('filters', filters, args));
  } else {
    data = await listThings(context, user, types, R.assoc('filters', filters, args));
  }
  // TODO #2341 JRI ADAPT THAT
  if (args.connectionFormat !== false) {
    const edges = [];
    for (let index = 0; index < data.edges.length; index += 1) {
      const edge = data.edges[index];
      const relIdObjects = edge.node[buildRefRelationKey(RELATION_OBJECT, ID_INTERNAL)] ?? [];
      const relInferredObjects = edge.node[buildRefRelationKey(RELATION_OBJECT, ID_INFERRED)] ?? [];
      const refTypes = [];
      if (relIdObjects.includes(containerId)) {
        refTypes.push('manual');
      }
      if (relInferredObjects.includes(containerId)) {
        refTypes.push('inferred');
      }
      edges.push({ ...edge, types: refTypes });
    }
    data.edges = edges;
  }
  return data;
};
export const relatedContainers = async (context, user, containerId, args) => {
  const key = buildRefRelationKey(RELATION_OBJECT);
  let types = ['Stix-Core-Object', 'stix-core-relationship'];
  if (args.viaTypes) {
    types = args.viaTypes;
  }
  const filters = [{ key, values: [containerId] }];
  const elements = await listAllThings(context, user, types, { filters });
  if (elements.length === 0) {
    return buildPagination(0, null, [], 0);
  }
  const elementsIds = elements.map((element) => element.id).slice(0, 800);
  const queryArgs = {
    ...args,
    filters: [...(args.filters || []), { key: buildRefRelationKey(RELATION_OBJECT), values: elementsIds }],
  };
  return findAll(context, user, queryArgs);
};
// endregion

export const containersObjectsOfObject = async (context, user, { id, types, filters = [], search = null }) => {
  const containers = await findAll(context, user, {
    first: 1000,
    search,
    filters: [...filters, { key: buildRefRelationKey(RELATION_OBJECT), values: [id] }],
  });
  const containersObjectsRelationshipsEdges = await Promise.all(
    R.map(
      (n) => listRelations(context, user, RELATION_OBJECT, {
        first: 1000,
        fromId: n.node.id,
        toTypes: types,
      }),
      containers.edges
    )
  );
  const containersObjectsRelationships = R.flatten(R.map((n) => n.edges, containersObjectsRelationshipsEdges));
  const containersObjects = await Promise.all(
    R.map((n) => storeLoadById(context, user, n.node.toId, n.node.toType), containersObjectsRelationships)
  );
  const containersObjectsResult = R.uniqBy(R.path(['node', 'id']), [
    ...containers.edges,
    ...containersObjectsRelationships,
    ...R.map((n) => ({ node: n }), containersObjects),
  ]);
  return buildPagination(0, null, containersObjectsResult, containersObjectsResult.length);
};
