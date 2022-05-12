import * as R from 'ramda';
import {
  createEntity,
  distributionEntities,
  internalLoadById,
  storeLoadById,
  timeSeriesEntities,
} from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { findAll as findIndividuals, addIndividual } from './individual';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_NOTE } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../schema/general';
import { elCount } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { isStixId } from '../schema/schemaUtils';

export const findById = (user, noteId) => {
  return storeLoadById(user, noteId, ENTITY_TYPE_CONTAINER_NOTE);
};

export const findAll = async (user, args) => {
  return listEntities(user, [ENTITY_TYPE_CONTAINER_NOTE], args);
};

export const noteContainsStixObjectOrStixRelationship = async (user, noteId, thingId) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(user, thingId)).id : thingId;
  const args = {
    filters: [
      { key: 'internal_id', values: [noteId] },
      { key: buildRefRelationKey(RELATION_OBJECT), values: [resolvedThingId] },
    ],
  };
  const noteFound = await findAll(user, args);
  return noteFound.edges.length > 0;
};

// region series
export const notesTimeSeries = (user, args) => {
  return timeSeriesEntities(user, ENTITY_TYPE_CONTAINER_NOTE, [], args);
};

export const notesNumber = (user, args) => ({
  count: elCount(user, READ_INDEX_STIX_DOMAIN_OBJECTS, R.assoc('types', [ENTITY_TYPE_CONTAINER_NOTE], args)),
  total: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(R.assoc('types', [ENTITY_TYPE_CONTAINER_NOTE]), R.dissoc('endDate'))(args)
  ),
});

export const notesTimeSeriesByEntity = (user, args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: args.objectId }];
  return timeSeriesEntities(user, ENTITY_TYPE_CONTAINER_NOTE, filters, args);
};

export const notesTimeSeriesByAuthor = async (user, args) => {
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
  return timeSeriesEntities(user, ENTITY_TYPE_CONTAINER_NOTE, filters, args);
};

export const notesNumberByEntity = (user, args) => ({
  count: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(
      R.assoc('isMetaRelationship', true),
      R.assoc('types', [ENTITY_TYPE_CONTAINER_NOTE]),
      R.assoc('relationshipType', RELATION_OBJECT),
      R.assoc('fromId', args.objectId)
    )(args)
  ),
  total: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(
      R.assoc('isMetaRelationship', true),
      R.assoc('types', [ENTITY_TYPE_CONTAINER_NOTE]),
      R.assoc('relationshipType', RELATION_OBJECT),
      R.assoc('fromId', args.objectId),
      R.dissoc('endDate')
    )(args)
  ),
});

export const notesDistributionByEntity = async (user, args) => {
  const { objectId } = args;
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: objectId }];
  return distributionEntities(user, ENTITY_TYPE_CONTAINER_NOTE, filters, args);
};
// endregion

// region mutations
export const addNote = async (user, note) => {
  const noteToCreate = note;
  // For note, auto assign current user as author
  if (!note.createdBy) {
    const args = { filters: [{ key: 'contact_information', values: [user.user_email] }], connectionFormat: false };
    const individuals = await findIndividuals(user, args);
    if (individuals.length > 0) {
      noteToCreate.createdBy = R.head(individuals).id;
    } else {
      const individual = await addIndividual(user, { name: user.name, contact_information: user.user_email });
      noteToCreate.createdBy = individual.id;
    }
  }
  const created = await createEntity(user, noteToCreate, ENTITY_TYPE_CONTAINER_NOTE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
// endregion
