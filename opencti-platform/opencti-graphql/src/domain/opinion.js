import { assoc, append, propOr, pipe } from 'ramda';
import {
  createEntity,
  distributionEntities,
  distributionEntitiesThroughRelations,
  escapeString,
  getSingleValueNumber,
  listEntities,
  listRelations,
  loadEntityById,
  prepareDate,
  timeSeriesEntities,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { notify } from '../database/redis';
import { findAll as findAllStixObservables } from './stixObservable';
import { findAll as findAllStixDomainEntities } from './stixDomainEntity';
import { ENTITY_TYPE_OPINION, RELATION_CREATED_BY, RELATION_OBJECT } from '../utils/idGenerator';

export const findById = (opinionId) => {
  return loadEntityById(opinionId, ENTITY_TYPE_OPINION);
};
export const findAll = async (args) => {
  return listEntities([ENTITY_TYPE_OPINION], ['name', 'description'], args);
};

// Entities tab
export const objectRefs = (opinionId, args) => {
  const key = `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`;
  const finalArgs = assoc('filters', append({ key, values: [opinionId] }, propOr([], 'filters', args)), args);
  return findAllStixDomainEntities(finalArgs);
};
export const opinionContainsStixDomainEntity = async (opinionId, objectId) => {
  const args = {
    filters: [
      { key: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`, values: [opinionId] },
      { key: 'internal_id', values: [objectId] },
    ],
  };
  const stixDomainEntities = await findAllStixDomainEntities(args);
  return stixDomainEntities.edges.length > 0;
};
// Relation refs
export const relationRefs = (opinionId, args) => {
  const relationFilter = { relation: RELATION_OBJECT, fromRole: 'so', toRole: 'knowledge_aggregation', id: opinionId };
  const finalArgs = assoc('relationFilter', relationFilter, args);
  return listRelations(args.relationType, finalArgs);
};
export const opinionContainsStixRelation = async (opinionId, objectId) => {
  const relationFilter = {
    relation: RELATION_OBJECT,
    fromRole: 'so',
    toRole: 'knowledge_aggregation',
    id: opinionId,
    relationId: objectId,
  };
  const stixRelations = await listRelations(null, { relationFilter });
  return stixRelations.edges.length > 0;
};
// Observable refs
export const observableRefs = (opinionId, args) => {
  const key = `${REL_INDEX_PREFIX}observable_refs.internal_id`;
  const finalArgs = assoc('filters', append({ key, values: [opinionId] }, propOr([], 'filters', args)), args);
  return findAllStixObservables(finalArgs);
};
export const opinionContainsStixObservable = async (opinionId, objectId) => {
  const args = {
    filters: [
      { key: `${REL_INDEX_PREFIX}observable_refs.internal_id`, values: [opinionId] },
      { key: 'internal_id', values: [objectId] },
    ],
  };
  const stixObservables = await findAllStixObservables(args);
  return stixObservables.edges.length > 0;
};
// region series
export const opinionsTimeSeries = (args) => {
  return timeSeriesEntities(ENTITY_TYPE_OPINION, [], args);
};
export const opinionsNumber = (args) => ({
  count: getSingleValueNumber(
    `match $x isa ${ENTITY_TYPE_OPINION}; ${
      args.endDate ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
    } get; count;`
  ),
  total: getSingleValueNumber(`match $x isa ${ENTITY_TYPE_OPINION}; get; count;`),
});
export const opinionsTimeSeriesByEntity = (args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: args.objectId }];
  return timeSeriesEntities(ENTITY_TYPE_OPINION, filters, args);
};
export const opinionsTimeSeriesByAuthor = async (args) => {
  const { authorId } = args;
  const filters = [{ isRelation: true, from: 'so', to: 'creator', type: RELATION_CREATED_BY, value: authorId }];
  return timeSeriesEntities(ENTITY_TYPE_OPINION, filters, args);
};
export const opinionsNumberByEntity = (args) => ({
  count: getSingleValueNumber(
    `match $x isa ${ENTITY_TYPE_OPINION};
    $rel(knowledge_aggregation:$x, so:$so) isa ${RELATION_OBJECT}; 
    $so has internal_id "${escapeString(args.objectId)}" ${
      args.endDate ? `; $x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
    }
    get;
    count;`
  ),
  total: getSingleValueNumber(
    `match $x isa ${ENTITY_TYPE_OPINION};
    $rel(knowledge_aggregation:$x, so:$so) isa ${RELATION_OBJECT}; 
    $so has internal_id "${escapeString(args.objectId)}";
    get;
    count;`
  ),
});
export const opinionsDistributionByEntity = async (args) => {
  const { objectId, field } = args;
  if (field.includes('.')) {
    const options = pipe(
      assoc('relationType', RELATION_OBJECT),
      assoc('toType', ENTITY_TYPE_OPINION),
      assoc('field', field.split('.')[1]),
      assoc('remoteRelationType', field.split('.')[0]),
      assoc('fromId', objectId)
    )(args);
    return distributionEntitiesThroughRelations(options);
  }
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: objectId }];
  return distributionEntities(ENTITY_TYPE_OPINION, filters, args);
};
// endregion

// region mutations
export const addOpinion = async (user, opinion) => {
  const created = await createEntity(user, opinion, ENTITY_TYPE_OPINION);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
// endregion
