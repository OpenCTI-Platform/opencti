import { ENTITY_TYPE_STREAM_COLLECTION, type BasicStoreEntityStreamCollection, type StoreEntityStreamCollection } from './streamCollection-types';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { delEditContext, notify, setEditContext } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { isUserHasCapability, MEMBER_ACCESS_RIGHT_VIEW, SETTINGS_SET_ACCESSES, SYSTEM_USER, TAXIIAPI_SETCOLLECTIONS } from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { validateFilterGroupForStixMatch } from '../../utils/filtering/filtering-stix/stix-filtering';
import { authorizedMembers } from '../../schema/attribute-definition';
import { TAXIIAPI } from '../../domain/user';
import { validatePublicUserId } from './dataSharing-utils';
import { getConsumersForCollection, getLocalConsumerMetrics } from '../../graphql/streamConsumerRegistry';
import { fetchStreamInfo } from '../../database/stream/stream-handler';
import { computeProcessingLagMetrics } from '../../utils/consumer-metrics';
import { getStreamProductionRate } from '../../database/redis-stream';
import type { AuthContext, AuthUser } from '../../types/user';
import type { EditContext, EditInput, QueryStreamCollectionsArgs, StreamCollectionAddInput } from '../../generated/graphql';

// Stream graphQL handlers
export const createStreamCollection = async (context: AuthContext, user: AuthUser, input: StreamCollectionAddInput) => {
  // our stix matching is currently limited, we need to validate the input filters
  if (input.filters) {
    validateFilterGroupForStixMatch(JSON.parse(input.filters));
  }
  if (input.stream_public && !isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    throw FunctionalError('You must have the SETTINGS_SETACCESSES capability to create a public stream collection');
  }
  if (input.stream_public && !input.stream_public_user_id) {
    throw FunctionalError('A user must be configured when the stream collection is public');
  }
  if (input.stream_public_user_id) {
    await validatePublicUserId(context, input.stream_public_user_id);
  }

  // Insert the collection
  const data = {
    authorized_authorities: [TAXIIAPI_SETCOLLECTIONS],
    ...input,
  };
  const { element, isCreation } = await createEntity(context, user, data, ENTITY_TYPE_STREAM_COLLECTION, { complete: true });
  if (isCreation) {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates live stream \`${data.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_STREAM_COLLECTION, input },
    });
  }
  return notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].ADDED_TOPIC, element, user);
};
export const findById = (context: AuthContext, user: AuthUser, collectionId: string) => {
  return storeLoadById<BasicStoreEntityStreamCollection>(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION);
};
export const findStreamCollectionPaginated = (context: AuthContext, user: AuthUser, args: QueryStreamCollectionsArgs) => {
  // If user is logged, list all streams where the user have access.
  if (user && isUserHasCapability(user, TAXIIAPI)) {
    // If user can manage the feeds, list everything related
    const options = { ...args, includeAuthorities: true };
    return pageEntitiesConnection<BasicStoreEntityStreamCollection>(context, user, [ENTITY_TYPE_STREAM_COLLECTION], options);
  }
  // No user specified, listing only public streams
  const filters = addFilter(args?.filters, 'stream_public', 'true');
  const publicArgs = { ...(args ?? {}), filters };
  return pageEntitiesConnection<BasicStoreEntityStreamCollection>(context, SYSTEM_USER, [ENTITY_TYPE_STREAM_COLLECTION], publicArgs);
};
export const streamCollectionEditField = async (context: AuthContext, user: AuthUser, collectionId: string, input: EditInput[]) => {
  const filtersItem = input.find((item) => item.key === 'filters');
  if (filtersItem?.value) {
    // our stix matching is currently limited, we need to validate the input filters
    validateFilterGroupForStixMatch(JSON.parse(filtersItem.value[0]));
  }
  const publicFields = ['stream_public', 'stream_public_user_id'];
  if (input.some((item) => publicFields.includes(item.key)) && !isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    throw FunctionalError('You must have the SETTINGS_SETACCESSES capability to modify public stream collection settings');
  }
  const publicUserIdItem = input.find((item) => item.key === 'stream_public_user_id');
  if (publicUserIdItem?.value?.[0]) {
    await validatePublicUserId(context, publicUserIdItem.value[0]);
  }
  const settingPublicTrue = input.find((item) => item.key === 'stream_public' && item.value?.[0] === 'true');
  if (settingPublicTrue) {
    const existingCollection = await findById(context, user, collectionId);
    const effectiveUserId = publicUserIdItem?.value?.[0] ?? existingCollection?.stream_public_user_id;
    if (!effectiveUserId) {
      throw FunctionalError('A user must be configured when the stream collection is public');
    }
  }
  const finalInput = input.map(({ key, value }) => {
    const item = { key, value };
    if (key === authorizedMembers.name) {
      item.value = value.map((id: string) => ({ id, access_right: MEMBER_ACCESS_RIGHT_VIEW }));
    }
    return item;
  });
  const { element } = await updateAttribute<StoreEntityStreamCollection>(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION, finalInput);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for live stream \`${element.name}\``,
    context_data: { id: collectionId, entity_type: ENTITY_TYPE_STREAM_COLLECTION, input },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].EDIT_TOPIC, element, user);
};
export const streamCollectionDelete = async (context: AuthContext, user: AuthUser, collectionId: string) => {
  const deleted = await deleteElementById<StoreEntityStreamCollection>(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes live stream \`${deleted.name}\``,
    context_data: { id: collectionId, entity_type: ENTITY_TYPE_STREAM_COLLECTION, input: deleted },
  });
  await notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].DELETE_TOPIC, deleted, user);
  return collectionId;
};
export const streamCollectionCleanContext = async (context: AuthContext, user: AuthUser, collectionId: string) => {
  await delEditContext(user, collectionId);
  return storeLoadById(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION).then((collectionToReturn) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].EDIT_TOPIC, collectionToReturn, user);
  });
};
export const streamCollectionEditContext = async (context: AuthContext, user: AuthUser, collectionId: string, input: EditContext) => {
  await setEditContext(user, collectionId, input);
  return storeLoadById(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION).then((collectionToReturn) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].EDIT_TOPIC, collectionToReturn, user);
  });
};

// Stream consumer monitoring
export const getStreamCollectionConsumers = async (collectionId: string) => {
  // getConsumersForCollection is now async and reads from Redis (all instances)
  const consumers = await getConsumersForCollection(collectionId);
  if (consumers.length === 0) {
    return [];
  }
  const streamInfo = await fetchStreamInfo();
  const streamProductionRate = await getStreamProductionRate();
  return consumers.map((consumer) => {
    const processingLagMetrics = computeProcessingLagMetrics(consumer.lastEventId, streamInfo, consumer.deliveryRate, streamProductionRate);
    return {
      connectionId: consumer.connectionId,
      userId: consumer.userId,
      userEmail: consumer.userEmail,
      connectedAt: consumer.connectedAt,
      lastEventId: consumer.lastEventId,
      productionRate: streamProductionRate,
      deliveryRate: consumer.deliveryRate,
      processingRate: consumer.processingRate,
      resolutionRate: consumer.resolutionRate,
      ...processingLagMetrics,
    };
  });
};

// Stream consumer information
export const getStreamConsumerInformation = async (channelId: string, lastEventId: string) => {
  const streamInfo = await fetchStreamInfo();
  const consumerMetrics = getLocalConsumerMetrics(channelId)!;
  const productionRate = await getStreamProductionRate();
  const computedLagsMetrics = computeProcessingLagMetrics(lastEventId, streamInfo, consumerMetrics.deliveryRate, productionRate);
  return { ...consumerMetrics, productionRate, ...computedLagsMetrics };
};
