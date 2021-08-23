/* eslint-disable camelcase */
import { elIndex } from '../database/elasticSearch';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_USER_SUBSCRIPTION } from '../schema/internalObject';
import { deleteElementById, listEntities, loadById, updateAttribute } from '../database/middleware';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';

// Stream graphQL handlers
export const createUserSubscription = async (user, input) => {
  const userSubscriptionId = generateInternalId();
  const data = {
    id: userSubscriptionId,
    internal_id: userSubscriptionId,
    standard_id: generateStandardId(ENTITY_TYPE_USER_SUBSCRIPTION, input),
    entity_type: ENTITY_TYPE_USER_SUBSCRIPTION,
    user_id: user.id,
    ...input,
  };
  await elIndex(INDEX_INTERNAL_OBJECTS, data);
  return data;
};
export const findById = async (user, collectionId) => {
  return loadById(user, collectionId, ENTITY_TYPE_USER_SUBSCRIPTION);
};
export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_USER_SUBSCRIPTION], args);
};
export const getUserSubscriptions = async (user, userId) => {
  const args = { filters: [{ key: 'user_id', values: [userId] }] };
  return findAll(user, args);
};
export const userSubscriptionEditField = async (user, collectionId, input) => {
  const { element } = await updateAttribute(user, collectionId, ENTITY_TYPE_USER_SUBSCRIPTION, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_USER_SUBSCRIPTION].EDIT_TOPIC, element, user);
};
export const userSubscriptionDelete = async (user, collectionId) => {
  await deleteElementById(user, collectionId, ENTITY_TYPE_USER_SUBSCRIPTION);
  return collectionId;
};
export const userSubscriptionCleanContext = async (user, collectionId) => {
  await delEditContext(user, collectionId);
  return loadById(user, collectionId, ENTITY_TYPE_USER_SUBSCRIPTION).then((collectionToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_USER_SUBSCRIPTION].EDIT_TOPIC, collectionToReturn, user)
  );
};
export const userSubscriptionEditContext = async (user, collectionId, input) => {
  await setEditContext(user, collectionId, input);
  return loadById(user, collectionId, ENTITY_TYPE_USER_SUBSCRIPTION).then((collectionToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_USER_SUBSCRIPTION].EDIT_TOPIC, collectionToReturn, user)
  );
};
