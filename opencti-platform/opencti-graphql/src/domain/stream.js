/* eslint-disable camelcase */
import * as R from 'ramda';
import { elIndex } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { extractEntityRepresentativeName } from '../database/entity-representative';
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
import { ABSTRACT_INTERNAL_RELATIONSHIP, BASE_TYPE_ENTITY, buildRefRelationKey } from '../schema/general';
import { getParentTypes } from '../schema/schemaUtils';
import { RELATION_ACCESSES_TO } from '../schema/internalRelationship';
import { isUserHasCapability, SYSTEM_USER, TAXIIAPI_SETCOLLECTIONS } from '../utils/access';
import { publishUserAction } from '../listener/UserActionListener';

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
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates live stream \`${data.name}\``,
    context_data: { id: collectionId, entity_type: ENTITY_TYPE_STREAM_COLLECTION, input }
  });
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
export const deleteGroupRelation = async (context, user, streamId, groupId) => {
  const { from, to } = await deleteRelationsByFromAndTo(context, user, groupId, streamId, RELATION_ACCESSES_TO, ABSTRACT_INTERNAL_RELATIONSHIP);
  const input = { fromId: groupId, toId: streamId, relationship_type: RELATION_ACCESSES_TO };
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `removes ${from.entity_type} \`${extractEntityRepresentativeName(from)}\` for live stream \`${to.name}\``,
    context_data: { id: groupId, entity_type: ENTITY_TYPE_STREAM_COLLECTION, input }
  });
  return findById(context, user, streamId);
};
export const createGroupRelation = async (context, user, streamId, groupId) => {
  const input = { fromId: groupId, toId: streamId, relationship_type: RELATION_ACCESSES_TO };
  const { from, to } = await createRelation(context, user, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `adds ${from.entity_type} \`${extractEntityRepresentativeName(from)}\` for live stream \`${to.name}\``,
    context_data: { id: groupId, entity_type: ENTITY_TYPE_STREAM_COLLECTION, input }
  });
  return findById(context, user, streamId);
};
export const findAll = (context, user, args) => {
  // If user is logged, list all streams where the user have access.
  if (user) {
    // If user can manage the feeds, list everything
    if (isUserHasCapability(user, TAXIIAPI_SETCOLLECTIONS)) {
      return listEntities(context, user, [ENTITY_TYPE_STREAM_COLLECTION], args);
    }
    // If user has no right to manage streams, only list the stream without groups or with correct groups
    const userGroupIds = (user.groups ?? []).map((g) => g.id);
    const accessFilter = { key: [buildRefRelationKey(RELATION_ACCESSES_TO)], values: [...userGroupIds, null] };
    const userArgs = { ...(args ?? {}), filters: [...(args?.filters ?? []), accessFilter] };
    return listEntities(context, user, [ENTITY_TYPE_STREAM_COLLECTION], userArgs);
  }
  // No user specify, listing only public streams
  const publicFilter = { key: ['stream_public'], values: ['true'] };
  const publicArgs = { ...(args ?? {}), filters: [...(args?.filters ?? []), publicFilter] };
  return listEntities(context, SYSTEM_USER, [ENTITY_TYPE_STREAM_COLLECTION], publicArgs);
};
export const streamCollectionEditField = async (context, user, collectionId, input) => {
  const { element } = await updateAttribute(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for live stream \`${element.name}\``,
    context_data: { id: collectionId, entity_type: ENTITY_TYPE_STREAM_COLLECTION, input }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].EDIT_TOPIC, element, user);
};
export const streamCollectionDelete = async (context, user, collectionId) => {
  const deleted = await deleteElementById(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes live stream \`${deleted.name}\``,
    context_data: { id: collectionId, entity_type: ENTITY_TYPE_STREAM_COLLECTION, input: deleted }
  });
  await notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].DELETE_TOPIC, deleted, user);
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
