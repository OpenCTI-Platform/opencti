/* eslint-disable camelcase */
import { elIndex } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_STREAM_COLLECTION } from '../schema/internalObject';
import { deleteElementById, updateAttribute, } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { BASE_TYPE_ENTITY } from '../schema/general';
import { getParentTypes } from '../schema/schemaUtils';
import { MEMBER_ACCESS_RIGHT_VIEW, SYSTEM_USER, TAXIIAPI_SETCOLLECTIONS } from '../utils/access';
import { publishUserAction } from '../listener/UserActionListener';

// Stream graphQL handlers
export const createStreamCollection = async (context, user, input) => {
  const collectionId = generateInternalId();
  // Insert the collection
  const data = {
    id: collectionId,
    internal_id: collectionId,
    standard_id: generateStandardId(ENTITY_TYPE_STREAM_COLLECTION, input),
    entity_type: ENTITY_TYPE_STREAM_COLLECTION,
    parent_types: getParentTypes(ENTITY_TYPE_STREAM_COLLECTION),
    base_type: BASE_TYPE_ENTITY,
    authorized_authorities: [TAXIIAPI_SETCOLLECTIONS],
    ...input
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
  return notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].ADDED_TOPIC, data, user);
};
export const findById = async (context, user, collectionId) => {
  return storeLoadById(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION);
};
export const findAll = (context, user, args) => {
  // If user is logged, list all streams where the user have access.
  if (user) {
    // If user can manage the feeds, list everything related
    const options = { ...args, includeAuthorities: true };
    return listEntities(context, user, [ENTITY_TYPE_STREAM_COLLECTION], options);
  }
  // No user specify, listing only public streams
  const publicFilter = { key: ['stream_public'], values: ['true'] };
  const publicArgs = { ...(args ?? {}), filters: [...(args?.filters ?? []), publicFilter] };
  return listEntities(context, SYSTEM_USER, [ENTITY_TYPE_STREAM_COLLECTION], publicArgs);
};
export const streamCollectionEditField = async (context, user, collectionId, input) => {
  const finalInput = input.map(({ key, value }) => {
    const item = { key, value };
    if (key === 'authorized_members') {
      item.value = value.map((id) => ({ id, access_right: MEMBER_ACCESS_RIGHT_VIEW }));
    }
    return item;
  });
  const { element } = await updateAttribute(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION, finalInput);
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
