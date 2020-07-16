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
import { findAll as findAllStixDomainEntities } from './stixDomainEntity';
import { ENTITY_TYPE_CONTAINER_NOTE, RELATION_CREATED_BY, RELATION_OBJECT } from '../utils/idGenerator';

export const findById = (noteId) => {
  return loadEntityById(noteId, ENTITY_TYPE_CONTAINER_NOTE);
};

export const findAll = async (args) => {
  return listEntities([ENTITY_TYPE_CONTAINER_NOTE], ['name', 'attribute_abstract', 'content'], args);
};

// Entities tab
export const objects = (noteId, args) => {
  const key = `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`;
  const finalArgs = assoc('filters', append({ key, values: [noteId] }, propOr([], 'filters', args)), args);
  // TODO @Julien : possible to have a method findAllStixCoreObjectOrStixRelationship?
  return findAllStixDomainEntities(finalArgs);
};

export const noteContainsStixCoreObjectOrStixRelationship = async (noteId, objectId) => {
  const args = {
    filters: [
      { key: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`, values: [noteId] },
      { key: 'internal_id', values: [objectId] },
    ],
  };
  // TODO @Julien : possible to have a method findAllStixCoreObjectOrStixRelationship?
  const stixCoreObjectsOrStixRelationships = await findAllStixDomainEntities(args);
  return stixCoreObjectsOrStixRelationships.edges.length > 0;
};

// region series
export const notesTimeSeries = (args) => {
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_NOTE, [], args);
};

export const notesNumber = (args) => ({
  count: getSingleValueNumber(
    `match $x isa Note; ${
      args.endDate ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
    } get; count;`
  ),
  total: getSingleValueNumber(`match $x isa ${ENTITY_TYPE_CONTAINER_NOTE}; get; count;`),
});

export const notesTimeSeriesByEntity = (args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: args.objectId }];
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_NOTE, filters, args);
};

export const notesTimeSeriesByAuthor = async (args) => {
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
  return timeSeriesEntities(ENTITY_TYPE_CONTAINER_NOTE, filters, args);
};

export const notesNumberByEntity = (args) => ({
  count: getSingleValueNumber(
    `match $x isa ${ENTITY_TYPE_CONTAINER_NOTE};
    $rel(${RELATION_OBJECT}_from:$x, ${RELATION_OBJECT}_to:$so) isa ${RELATION_OBJECT}; 
    $so has internal_id "${escapeString(args.objectId)}" ${
      args.endDate ? `; $x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
    }
    get;
    count;`
  ),
  total: getSingleValueNumber(
    `match $x isa ${ENTITY_TYPE_CONTAINER_NOTE};
    $rel(${RELATION_OBJECT}_from:$x, ${RELATION_OBJECT}_to:$so) isa ${RELATION_OBJECT}; 
    $so has internal_id "${escapeString(args.objectId)}";
    get;
    count;`
  ),
});

export const notesDistributionByEntity = async (args) => {
  const { objectId, field } = args;
  if (field.includes('.')) {
    const options = pipe(
      assoc('relationType', RELATION_OBJECT),
      assoc('toType', ENTITY_TYPE_CONTAINER_NOTE),
      assoc('field', field.split('.')[1]),
      assoc('remoteRelationType', field.split('.')[0]),
      assoc('fromId', objectId)
    )(args);
    return distributionEntitiesThroughRelations(options);
  }
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: objectId }];
  return distributionEntities(ENTITY_TYPE_CONTAINER_NOTE, filters, args);
};
// endregion

// region mutations
export const addNote = async (user, note) => {
  const created = await createEntity(user, note, ENTITY_TYPE_CONTAINER_NOTE);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
// endregion
