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
import { TYPE_OPENCTI_INTERNAL } from '../database/utils';

export const findById = (tagId) => {
  return loadEntityById(tagId, 'Tag');
};
export const findAll = (args) => {
  return listEntities(['Tag'], ['value', 'tag_type'], args);
};

export const addTag = async (user, tag) => {
  const created = await createEntity(user, tag, 'Tag', { modelType: TYPE_OPENCTI_INTERNAL, noLog: true });
  return notify(BUS_TOPICS.Tag.ADDED_TOPIC, created, user);
};
export const tagDelete = (user, tagId) => deleteEntityById(user, tagId, 'Tag', { noLog: true });

export const tagEditField = (user, tagId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, tagId, 'Tag', input, wTx, { noLog: true });
  }).then(async () => {
    const tag = await loadEntityById(tagId, 'Tag');
    return notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user);
  });
};

export const tagCleanContext = (user, tagId) => {
  delEditContext(user, tagId);
  return loadEntityById(tagId, 'Tag').then((tag) => notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user));
};
export const tagEditContext = (user, tagId, input) => {
  setEditContext(user, tagId, input);
  return loadEntityById(tagId, 'Tag').then((tag) => notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user));
};
