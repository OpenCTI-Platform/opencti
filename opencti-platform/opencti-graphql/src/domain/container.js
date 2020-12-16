import { assoc, append, propOr, filter, concat } from 'ramda';
import { findAll as findAllStixCoreObjects } from './stixCoreObject';
import { findAll as findAllStixCoreRelationships } from './stixCoreRelationship';
import { RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { listEntities, loadById } from '../database/middleware';
import { ENTITY_TYPE_CONTAINER, REL_INDEX_PREFIX } from '../schema/general';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { isStixCoreObject } from '../schema/stixCoreObject';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';

export const STATUS_STATUS_PROGRESS = 1;
export const STATUS_STATUS_ANALYZED = 2;
export const STATUS_STATUS_CLOSED = 3;

export const findById = async (containerId) => {
  return loadById(containerId, ENTITY_TYPE_CONTAINER);
};

export const findAll = async (args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = filter((type) => isStixDomainObjectContainer(type), args.types);
  }
  if (types.length === 0) {
    types.push(ENTITY_TYPE_CONTAINER);
  }
  return listEntities(types, args);
};

// Entities tab
export const objects = async (containerId, args) => {
  const key = `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`;
  const stixCoreObjectArgs = assoc(
    'filters',
    append({ key, values: [containerId] }, propOr([], 'filters', args)),
    args
  );
  const relationFilter = {
    relation: 'object',
    fromRole: 'object_to',
    toRole: 'object_from',
    id: containerId,
  };
  const stixCoreRelationshipsArgs = assoc('relationFilter', relationFilter, args);
  if (args.types && args.types.length > 0) {
    let haveStixCoreObjectInTypes = false;
    let haveStixCoreRelationshipInTypes = false;
    // eslint-disable-next-line no-restricted-syntax
    for (const type of args.types) {
      if (isStixCoreObject(type)) {
        haveStixCoreObjectInTypes = true;
      }
      if (isStixCoreRelationship(type)) {
        haveStixCoreRelationshipInTypes = true;
      }
    }
    if (haveStixCoreObjectInTypes && !haveStixCoreRelationshipInTypes) {
      return findAllStixCoreObjects(stixCoreObjectArgs);
    }
    if (haveStixCoreRelationshipInTypes && !haveStixCoreObjectInTypes) {
      return findAllStixCoreRelationships(stixCoreRelationshipsArgs);
    }
  }
  const stixCoreObjects = await findAllStixCoreObjects(stixCoreObjectArgs);
  const stixCoreRelationships = await findAllStixCoreRelationships(stixCoreRelationshipsArgs);
  return assoc('edges', concat(stixCoreObjects.edges, stixCoreRelationships.edges), stixCoreObjects);
};
// endregion
