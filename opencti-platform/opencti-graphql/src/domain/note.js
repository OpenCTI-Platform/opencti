import { assoc, dissoc, pipe } from 'ramda';
import { createEntity, distributionEntities, timeSeriesEntities } from '../database/middleware';
import { internalLoadById, listEntitiesPaginated, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_NOTE } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../schema/general';
import { now } from '../utils/format';
import { isStixId } from '../schema/schemaUtils';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixRefRelationship';
import { elCount } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { addFilter } from '../utils/filtering/filtering-utils';

export const findById = (context, user, noteId) => {
  return storeLoadById(context, user, noteId, ENTITY_TYPE_CONTAINER_NOTE);
};

export const findNotePaginated = async (context, user, args) => {
  return listEntitiesPaginated(context, user, [ENTITY_TYPE_CONTAINER_NOTE], args);
};

// region mutations
export const addNote = async (context, user, note) => {
  const noteToCreate = note.created ? note : { ...note, created: now() };
  const created = await createEntity(context, user, noteToCreate, ENTITY_TYPE_CONTAINER_NOTE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
// endregion

// Entities tab

export const noteContainsStixObjectOrStixRelationship = async (context, user, noteId, thingId) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).id : thingId;
  const args = {
    filters: {
      mode: 'and',
      filters: [
        { key: 'internal_id', values: [noteId] },
        { key: buildRefRelationKey(RELATION_OBJECT), values: [resolvedThingId] },
      ],
      filterGroups: [],
    },
  };
  const noteFound = await findNotePaginated(context, user, args);
  return noteFound.edges.length > 0;
};

// region series
export const notesTimeSeries = (context, user, args) => {
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_NOTE], args);
};

export const notesNumber = (context, user, args) => ({
  count: elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, assoc('types', [ENTITY_TYPE_CONTAINER_NOTE], args)),
  total: elCount(
    context,
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    pipe(assoc('types', [ENTITY_TYPE_CONTAINER_NOTE]), dissoc('endDate'))(args)
  ),
});

export const notesTimeSeriesByEntity = (context, user, args) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_NOTE], { ...args, filters });
};

export const notesTimeSeriesByAuthor = async (context, user, args) => {
  const { authorId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_CREATED_BY, '*'), authorId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_NOTE], { ...args, filters });
};

export const notesNumberByEntity = (context, user, args) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  return {
    count: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...args, filters, types: [ENTITY_TYPE_CONTAINER_NOTE] },
    ),
    total: elCount(
      context,
      user,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      { ...args, filters, types: [ENTITY_TYPE_CONTAINER_NOTE] },
    ),
  };
};

export const notesDistributionByEntity = async (context, user, args) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  return distributionEntities(context, user, [ENTITY_TYPE_CONTAINER_NOTE], { ...args, filters });
};
// endregion
