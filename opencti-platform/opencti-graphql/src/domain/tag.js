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
import { ENTITY_TYPE_TAG } from '../utils/idGenerator';

export const findById = (tagId) => {
  return loadEntityById(tagId, ENTITY_TYPE_TAG);
};
export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_TAG], ['value', 'tag_type'], args);
};

export const addTag = async (user, tag) => {
  const created = await createEntity(user, tag, ENTITY_TYPE_TAG, { noLog: true });
  return notify(BUS_TOPICS.Tag.ADDED_TOPIC, created, user);
};
export const tagDelete = (user, tagId) => deleteEntityById(user, tagId, ENTITY_TYPE_TAG, { noLog: true });

export const tagEditField = (user, tagId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, tagId, ENTITY_TYPE_TAG, input, wTx, { noLog: true });
  }).then(async () => {
    const tag = await loadEntityById(tagId, ENTITY_TYPE_TAG);
    return notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user);
  });
};

export const tagCleanContext = (user, tagId) => {
  delEditContext(user, tagId);
  return loadEntityById(tagId, ENTITY_TYPE_TAG).then((tag) => notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user));
};
export const tagEditContext = (user, tagId, input) => {
  setEditContext(user, tagId, input);
  return loadEntityById(tagId, ENTITY_TYPE_TAG).then((tag) => notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user));
};
