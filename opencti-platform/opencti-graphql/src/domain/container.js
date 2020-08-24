import { assoc, append, propOr, filter, concat } from 'ramda';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { findAll as findAllStixCoreObjects } from './stixCoreObject';
import { findAll as findAllStixCoreRelationships } from './stixCoreRelationship';
import { RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { listEntities, loadEntityById } from '../database/grakn';
import { ENTITY_TYPE_CONTAINER } from '../schema/general';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { isStixCoreObject } from '../schema/stixCoreObject';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';

export const STATUS_STATUS_NEW = 0;
export const STATUS_STATUS_PROGRESS = 1;
export const STATUS_STATUS_ANALYZED = 2;
export const STATUS_STATUS_CLOSED = 3;

export const findById = async (identityId) => {
  return loadEntityById(identityId, ENTITY_TYPE_CONTAINER);
};

export const findAll = async (args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = filter((type) => isStixDomainObjectContainer(type), args.types);
  }
  if (types.length === 0) {
    types.push(ENTITY_TYPE_CONTAINER);
  }
  return listEntities(types, ['name', 'description'], args);
};

// Entities tab
export const objects = async (containerId, args) => {
  const key = `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`;
  const finalArgs = assoc('filters', append({ key, values: [containerId] }, propOr([], 'filters', args)), args);
  if (args.types && args.types.length > 0) {
    if (isStixCoreObject(args.types[0])) {
      return findAllStixCoreObjects(finalArgs);
    }
    if (isStixCoreRelationship(args.types[0])) {
      return findAllStixCoreRelationships(finalArgs);
    }
  }
  const stixCoreObjects = await findAllStixCoreObjects(finalArgs);
  const stixCoreRelationships = await findAllStixCoreRelationships(finalArgs);
  return assoc('edges', concat(stixCoreObjects.edges, stixCoreRelationships.edges), stixCoreObjects);
};
// endregion
