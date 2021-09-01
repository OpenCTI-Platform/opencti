/* eslint-disable camelcase */
import { elIndex } from '../database/elasticSearch';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_STREAM_COLLECTION } from '../schema/internalObject';
import { deleteElementById, listEntities, loadById, updateAttribute } from '../database/middleware';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { BASE_TYPE_ENTITY } from '../schema/general';
import { getParentTypes } from '../schema/schemaUtils';

// Stream graphQL handlers
export const createStreamCollection = async (user, input) => {
  const collectionId = generateInternalId();
  const data = {
    id: collectionId,
    internal_id: collectionId,
    standard_id: generateStandardId(ENTITY_TYPE_STREAM_COLLECTION, input),
    entity_type: ENTITY_TYPE_STREAM_COLLECTION,
    parent_types: getParentTypes(ENTITY_TYPE_STREAM_COLLECTION),
    base_type: BASE_TYPE_ENTITY,
    ...input,
  };
  await elIndex(INDEX_INTERNAL_OBJECTS, data);
  return data;
};
export const findById = async (user, collectionId) => {
  return loadById(user, collectionId, ENTITY_TYPE_STREAM_COLLECTION);
};
export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_STREAM_COLLECTION], args);
};
export const streamCollectionEditField = async (user, collectionId, input) => {
  const { element } = await updateAttribute(user, collectionId, ENTITY_TYPE_STREAM_COLLECTION, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].EDIT_TOPIC, element, user);
};
export const streamCollectionDelete = async (user, collectionId) => {
  await deleteElementById(user, collectionId, ENTITY_TYPE_STREAM_COLLECTION);
  return collectionId;
};
export const streamCollectionCleanContext = async (user, collectionId) => {
  await delEditContext(user, collectionId);
  return loadById(user, collectionId, ENTITY_TYPE_STREAM_COLLECTION).then((collectionToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].EDIT_TOPIC, collectionToReturn, user)
  );
};
export const streamCollectionEditContext = async (user, collectionId, input) => {
  await setEditContext(user, collectionId, input);
  return loadById(user, collectionId, ENTITY_TYPE_STREAM_COLLECTION).then((collectionToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].EDIT_TOPIC, collectionToReturn, user)
  );
};
