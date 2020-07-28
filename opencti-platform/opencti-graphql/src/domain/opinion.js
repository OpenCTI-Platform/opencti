import { assoc, append, propOr, pipe } from 'ramda';
import {
  createEntity,
  distributionEntities,
  distributionEntitiesThroughRelations,
  escapeString,
  getSingleValueNumber,
  listEntities,
  loadEntityById,
  prepareDate,
  timeSeriesEntities,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { notify } from '../database/redis';
import { findAll as findAllStixDomainEntities } from './stixDomainObject';
import {
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ENTITY_TYPE_CONTAINER_OPINION,
  RELATION_CREATED_BY,
  RELATION_OBJECT,
} from '../utils/idGenerator';

export const findById = (opinionId) => {
  return loadEntityById(opinionId, ENTITY_TYPE_CONTAINER_OPINION);
};
export const findAll = async (args) => {
  return listEntities([ENTITY_TYPE_CONTAINER_OPINION], ['name', 'description'], args);
};

// Entities tab
export const objects = (noteId, args) => {
  const key = `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`;
  const finalArgs = assoc('filters', append({ key, values: [noteId] }, propOr([], 'filters', args)), args);
  // TODO @Julien : possible to have a method findAllStixCoreObjectOrStixRelationship?
  return findAllStixDomainEntities(finalArgs);
};

export const opinionContainsStixCoreObjectOrStixRelationship = async (noteId, objectId) => {
  const args = {
    filters: [
      {
        key: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`,
        values: [noteId],
      },
      {
        key: 'internal_id',
        values: [objectId],
      },
    ],
  };
  // TODO @Julien : possible to have a method findAllStixCoreObjectOrStixRelationship?
  const stixCoreObjectsOrStixRelationships = await findAllStixDomainEntities(args);
  return stixCoreObjectsOrStixRelationships.edges.length > 0;
};

// region series
export const opinionsTimeSeries = (args) => {
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_OPINION, [], args);
};

export const opinionsNumber = (args) => ({
  count: getSingleValueNumber(
    `match $x isa ${ENTITY_TYPE_CONTAINER_OPINION}; ${
      args.endDate ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
    } get; count;`
  ),
  total: getSingleValueNumber(`match $x isa ${ENTITY_TYPE_CONTAINER_OPINION}; get; count;`),
});

export const opinionsTimeSeriesByEntity = (args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: args.objectId }];
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_OPINION, filters, args);
};

export const opinionsTimeSeriesByAuthor = async (args) => {
  const { authorId } = args;
  const filters = [
    {
      isRelation: true,
      from: `${RELATION_CREATED_BY}_from`,
      to: `${RELATION_CREATED_BY}_to`,
      type: RELATION_CREATED_BY,
      value: authorId,
    },
  ];
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_OPINION, filters, args);
};

export const opinionsNumberByEntity = (args) => ({
  count: getSingleValueNumber(
    `match $x isa ${ENTITY_TYPE_CONTAINER_OPINION};
    $rel(${RELATION_OBJECT}_from:$x, ${RELATION_OBJECT}_to:$so) isa ${RELATION_OBJECT}; 
    $so has internal_id "${escapeString(args.objectId)}" ${
      args.endDate ? `; $x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
    }
    get;
    count;`
  ),
  total: getSingleValueNumber(
    `match $x isa ${ENTITY_TYPE_CONTAINER_OPINION};
    $rel(${RELATION_OBJECT}_from:$x, ${RELATION_OBJECT}_to:$so) isa ${RELATION_OBJECT}; 
    $so has internal_id "${escapeString(args.objectId)}";
    get;
    count;`
  ),
});

export const opinionsDistributionByEntity = async (args) => {
  const { objectId, field } = args;
  if (field.includes('.')) {
    const options = pipe(
      assoc('relationship_type', RELATION_OBJECT),
      assoc('toType', ENTITY_TYPE_CONTAINER_OPINION),
      assoc('field', field.split('.')[1]),
      assoc('remoterelationship_type', field.split('.')[0]),
      assoc('fromId', objectId)
    )(args);
    return distributionEntitiesThroughRelations(options);
  }
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: objectId }];
  return distributionEntities(ENTITY_TYPE_CONTAINER_OPINION, filters, args);
};
// endregion

// region mutations
export const addOpinion = async (user, opinion) => {
  const created = await createEntity(user, opinion, ENTITY_TYPE_CONTAINER_OPINION);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
// endregion
