import { createEntity, storeLoadById, } from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_NOTE } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { now } from '../utils/format';

export const findById = (context, user, noteId) => {
  return storeLoadById(context, user, noteId, ENTITY_TYPE_CONTAINER_NOTE);
};

export const findAll = async (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_CONTAINER_NOTE], args);
};

// region mutations
export const addNote = async (context, user, note) => {
  const noteToCreate = note.created ? note : { ...note, created: now() };
  const created = await createEntity(context, user, noteToCreate, ENTITY_TYPE_CONTAINER_NOTE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
// endregion
