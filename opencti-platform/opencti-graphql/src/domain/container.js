import * as R from 'ramda';
import { RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { paginateAllThings, listEntities, listThings, loadById } from '../database/middleware';
import { buildRefRelationKey, ENTITY_TYPE_CONTAINER } from '../schema/general';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { buildPagination } from '../database/utils';

export const STATUS_STATUS_PROGRESS = 1;
export const STATUS_STATUS_ANALYZED = 2;
export const STATUS_STATUS_CLOSED = 3;

export const findById = async (user, containerId) => {
  return loadById(user, containerId, ENTITY_TYPE_CONTAINER);
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
  let types = ['Stix-Core-Object', 'stix-core-relationship'];
  if (args.types) {
    types = args.types;
  }
  const filters = [{ key, values: [containerId] }, ...(args.filters || [])];
  if (args.all) {
    return paginateAllThings(user, types, R.assoc('filters', filters, args));
  }
  return listThings(user, types, R.assoc('filters', filters, args));
};
// endregion

export const containersObjectsOfObject = async (user, { id, types, filters = [], search = null }) => {
  const containers = await findAll(user, {
    connectionFormat: false,
    first: 500,
    search,
    filters: [...filters, { key: buildRefRelationKey(RELATION_OBJECT), values: [id] }],
  });
  const containersObjects = await Promise.all(R.map((n) => objects(user, n.id, { first: 1000, types }), containers));
  const containersObjectsResult = R.uniqBy(R.path(['node', 'id']), R.flatten(R.map((n) => n.edges, containersObjects)));
  return buildPagination(0, null, containersObjectsResult, containersObjectsResult.length);
};
