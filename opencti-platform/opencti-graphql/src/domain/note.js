import { assoc, dissoc, pipe } from 'ramda';
import {
  createEntity,
  distributionEntities,
  listEntities,
  loadById,
  timeSeriesEntities,
} from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_NOTE } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT, REL_INDEX_PREFIX } from '../schema/general';
import { elCount } from '../database/elasticSearch';
import { INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';

export const findById = (noteId) => {
  return loadById(noteId, ENTITY_TYPE_CONTAINER_NOTE);
};

export const findAll = async (args) => {
  return listEntities([ENTITY_TYPE_CONTAINER_NOTE], args);
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
  count: elCount(INDEX_STIX_DOMAIN_OBJECTS, assoc('types', [ENTITY_TYPE_CONTAINER_NOTE], args)),
  total: elCount(
    INDEX_STIX_DOMAIN_OBJECTS,
    pipe(assoc('types', [ENTITY_TYPE_CONTAINER_NOTE]), dissoc('endDate'))(args)
  ),
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
  count: elCount(
    INDEX_STIX_DOMAIN_OBJECTS,
    pipe(
      assoc('isMetaRelationship', true),
      assoc('types', [ENTITY_TYPE_CONTAINER_NOTE]),
      assoc('relationshipType', RELATION_OBJECT),
      assoc('fromId', args.objectId)
    )(args)
  ),
  total: elCount(
    INDEX_STIX_DOMAIN_OBJECTS,
    pipe(
      assoc('isMetaRelationship', true),
      assoc('types', [ENTITY_TYPE_CONTAINER_NOTE]),
      assoc('relationshipType', RELATION_OBJECT),
      assoc('fromId', args.objectId),
      dissoc('endDate')
    )(args)
  ),
});

export const notesDistributionByEntity = async (args) => {
  const { objectId } = args;
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
