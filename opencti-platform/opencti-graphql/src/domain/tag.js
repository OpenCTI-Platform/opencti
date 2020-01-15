import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  executeWrite,
  listEntities,
  loadEntityById,
  TYPE_OPENCTI_INTERNAL,
  updateAttribute
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findById = tagId => {
  return loadEntityById(tagId);
};
export const findAll = args => {
  return listEntities(['Tag'], ['value', 'tag_type'], args);
};

export const addTag = async (user, tag) => {
  const created = await createEntity(tag, 'Tag', { modelType: TYPE_OPENCTI_INTERNAL });
  return notify(BUS_TOPICS.Tag.ADDED_TOPIC, created, user);
};
export const tagDelete = tagId => deleteEntityById(tagId);
export const tagAddRelation = (user, tagId, input) => {
  return createRelation(tagId, input).then(relationData => {
    notify(BUS_TOPICS.Tag.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const tagDeleteRelation = async (user, tagId, relationId) => {
  await deleteRelationById(relationId);
  const data = await loadEntityById(tagId);
  return notify(BUS_TOPICS.Tag.EDIT_TOPIC, data, user);
};
export const tagEditField = (user, tagId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(tagId, input, wTx);
  }).then(async () => {
    const tag = await loadEntityById(tagId);
    return notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user);
  });
};

export const tagCleanContext = (user, tagId) => {
  delEditContext(user, tagId);
  return loadEntityById(tagId).then(tag => notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user));
};
export const tagEditContext = (user, tagId, input) => {
  setEditContext(user, tagId, input);
  return loadEntityById(tagId).then(tag => notify(BUS_TOPICS.Tag.EDIT_TOPIC, tag, user));
};
