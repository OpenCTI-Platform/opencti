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
  updateAttribute,
} from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { ABSTRACT_INTERNAL_RELATIONSHIP, BASE_TYPE_ENTITY } from '../schema/general';
import { getParentTypes } from '../schema/schemaUtils';
import { RELATION_ACCESSES_TO } from '../schema/internalRelationship';

// Stream graphQL handlers
export const createStreamCollection = async (context, user, input) => {
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
  await createRelations(context, user, relatedGroups.map((g) => relBuilder(g)));
  return notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].ADDED_TOPIC, data, user);
};
export const streamCollectionGroups = async (context, user, collection) => {
  return listThroughGetFrom(context, user, collection.id, RELATION_ACCESSES_TO, ENTITY_TYPE_GROUP);
};
export const findById = async (context, user, collectionId) => {
  return storeLoadById(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION);
};
export const deleteGroupRelation = async (context, user, collectionId, groupId) => {
  await deleteRelationsByFromAndTo(context, user, groupId, collectionId, RELATION_ACCESSES_TO, ABSTRACT_INTERNAL_RELATIONSHIP);
  return findById(context, user, collectionId);
};
export const createGroupRelation = async (context, user, collectionId, groupId) => {
  await createRelation(context, user, { fromId: groupId, toId: collectionId, relationship_type: RELATION_ACCESSES_TO });
  return findById(context, user, collectionId);
};
export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_STREAM_COLLECTION], args);
};
export const streamCollectionEditField = async (context, user, collectionId, input) => {
  const { element } = await updateAttribute(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].EDIT_TOPIC, element, user);
};
export const streamCollectionDelete = async (context, user, collectionId) => {
  await deleteElementById(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION);
  return collectionId;
};
export const streamCollectionCleanContext = async (context, user, collectionId) => {
  await delEditContext(user, collectionId);
  return storeLoadById(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION).then((collectionToReturn) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].EDIT_TOPIC, collectionToReturn, user);
  });
};
export const streamCollectionEditContext = async (context, user, collectionId, input) => {
  await setEditContext(user, collectionId, input);
  return storeLoadById(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION).then((collectionToReturn) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].EDIT_TOPIC, collectionToReturn, user);
  });
};
