import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  deleteEntityById,
  executeWrite,
  listEntities,
  loadEntityById,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { ENTITY_TYPE_LABEL } from '../utils/idGenerator';

export const findById = (tagId) => {
  return loadEntityById(tagId, ENTITY_TYPE_LABEL);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_LABEL], ['value'], args);
};

export const addLabel = async (user, tag) => {
  const created = await createEntity(user, tag, ENTITY_TYPE_LABEL, { noLog: true });
  return notify(BUS_TOPICS.Label.ADDED_TOPIC, created, user);
};

export const labelDelete = (user, tagId) => deleteEntityById(user, tagId, ENTITY_TYPE_LABEL, { noLog: true });

export const labelEditField = (user, tagId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, tagId, ENTITY_TYPE_LABEL, input, wTx, { noLog: true });
  }).then(async () => {
    const tag = await loadEntityById(tagId, ENTITY_TYPE_LABEL);
    return notify(BUS_TOPICS.Label.EDIT_TOPIC, tag, user);
  });
};

export const labelCleanContext = async (user, tagId) => {
  delEditContext(user, tagId);
  return loadEntityById(tagId, ENTITY_TYPE_LABEL).then((tag) => notify(BUS_TOPICS.Label.EDIT_TOPIC, tag, user));
};

export const labelEditContext = async (user, tagId, input) => {
  await setEditContext(user, tagId, input);
  return loadEntityById(tagId, ENTITY_TYPE_LABEL).then((tag) => notify(BUS_TOPICS.Label.EDIT_TOPIC, tag, user));
};
