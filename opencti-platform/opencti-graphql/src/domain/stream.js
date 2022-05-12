/* eslint-disable camelcase */
import * as R from 'ramda';
import { elIndex } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_STREAM_COLLECTION } from '../schema/internalObject';
import {
  createRelation,
  createRelations,
  deleteElementById,
  deleteRelationsByFromAndTo,
  listThroughGetFrom,
  storeLoadById,
  updateAttribute,
} from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { ABSTRACT_INTERNAL_RELATIONSHIP, BASE_TYPE_ENTITY } from '../schema/general';
import { getParentTypes } from '../schema/schemaUtils';
import { RELATION_ACCESSES_TO } from '../schema/internalRelationship';

// Stream graphQL handlers
export const createStreamCollection = async (user, input) => {
  const collectionId = generateInternalId();
  const relatedGroups = input.groups || [];
  // Insert the collection
  const data = {
    id: collectionId,
    internal_id: collectionId,
    standard_id: generateStandardId(ENTITY_TYPE_STREAM_COLLECTION, input),
    entity_type: ENTITY_TYPE_STREAM_COLLECTION,
    parent_types: getParentTypes(ENTITY_TYPE_STREAM_COLLECTION),
    base_type: BASE_TYPE_ENTITY,
    ...R.dissoc('groups', input),
  };
  await elIndex(INDEX_INTERNAL_OBJECTS, data);
  // Create groups relations
  const relBuilder = (g) => ({ fromId: g, toId: collectionId, relationship_type: RELATION_ACCESSES_TO });
  await createRelations(
    user,
    relatedGroups.map((g) => relBuilder(g))
  );
  return data;
};
export const streamCollectionGroups = async (user, collection) => {
  return listThroughGetFrom(user, collection.id, RELATION_ACCESSES_TO, ENTITY_TYPE_GROUP);
};
export const findById = async (user, collectionId) => {
  return storeLoadById(user, collectionId, ENTITY_TYPE_STREAM_COLLECTION);
};
export const deleteGroupRelation = async (user, collectionId, groupId) => {
  await deleteRelationsByFromAndTo(user, groupId, collectionId, RELATION_ACCESSES_TO, ABSTRACT_INTERNAL_RELATIONSHIP);
  return findById(user, collectionId);
};
export const createGroupRelation = async (user, collectionId, groupId) => {
  await createRelation(user, { fromId: groupId, toId: collectionId, relationship_type: RELATION_ACCESSES_TO });
  return findById(user, collectionId);
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
  return storeLoadById(user, collectionId, ENTITY_TYPE_STREAM_COLLECTION).then((collectionToReturn) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].EDIT_TOPIC, collectionToReturn, user);
  });
};
export const streamCollectionEditContext = async (user, collectionId, input) => {
  await setEditContext(user, collectionId, input);
  return storeLoadById(user, collectionId, ENTITY_TYPE_STREAM_COLLECTION).then((collectionToReturn) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].EDIT_TOPIC, collectionToReturn, user);
  });
};
