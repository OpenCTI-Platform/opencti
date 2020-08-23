import { assoc, pipe } from 'ramda';
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
import { ENTITY_TYPE_CONTAINER_NOTE } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (noteId) => {
  return loadEntityById(noteId, ENTITY_TYPE_CONTAINER_NOTE);
};

export const findAll = async (args) => {
  return listEntities([ENTITY_TYPE_CONTAINER_NOTE], ['name', 'attribute_abstract', 'content'], args);
};

export const noteContainsStixObjectOrStixRelationship = async (noteId, thingId) => {
  const args = {
    filters: [
      { key: 'internal_id', values: [noteId] },
      { key: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`, values: [thingId] },
    ],
  };
  const noteFound = await findAll(args);
  return noteFound.edges.length > 0;
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
      assoc('relationshipType', RELATION_OBJECT),
      assoc('toType', ENTITY_TYPE_CONTAINER_NOTE),
      assoc('field', field.split('.')[1]),
      assoc('remoteRelationshipType', field.split('.')[0]),
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
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
// endregion
