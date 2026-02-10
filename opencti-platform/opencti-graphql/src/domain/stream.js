/* eslint-disable camelcase */
import { ENTITY_TYPE_STREAM_COLLECTION } from '../schema/internalObject';
import { createEntity, deleteElementById, updateAttribute } from '../database/middleware';
import { pageEntitiesConnection, storeLoadById } from '../database/middleware-loader';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { isUserHasCapability, MEMBER_ACCESS_RIGHT_VIEW, SYSTEM_USER, TAXIIAPI_SETCOLLECTIONS } from '../utils/access';
import { publishUserAction } from '../listener/UserActionListener';
import { addFilter } from '../utils/filtering/filtering-utils';
import { validateFilterGroupForStixMatch } from '../utils/filtering/filtering-stix/stix-filtering';
import { authorizedMembers } from '../schema/attribute-definition';
import { TAXIIAPI } from './user';
import { getConsumersForCollection } from '../graphql/streamConsumerRegistry';
import { fetchStreamInfo, fetchStreamProductionRate } from '../database/stream/stream-handler';
import { utcDate } from '../utils/format';

// Stream graphQL handlers
export const createStreamCollection = async (context, user, input) => {
  // our stix matching is currently limited, we need to validate the input filters
  if (input.filters) {
    validateFilterGroupForStixMatch(JSON.parse(input.filters));
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
export const findById = async (context, user, collectionId) => {
  return storeLoadById(context, user, collectionId, ENTITY_TYPE_STREAM_COLLECTION);
};
export const findStreamCollectionPaginated = (context, user, args) => {
  // If user is logged, list all streams where the user have access.
  if (user && isUserHasCapability(user, TAXIIAPI)) {
    // If user can manage the feeds, list everything related
    const options = { ...args, includeAuthorities: true };
    return pageEntitiesConnection(context, user, [ENTITY_TYPE_STREAM_COLLECTION], options);
  }
  // No user specify, listing only public streams
  const filters = addFilter(args?.filters, 'stream_public', 'true');
  const publicArgs = { ...(args ?? {}), filters };
  return pageEntitiesConnection(context, SYSTEM_USER, [ENTITY_TYPE_STREAM_COLLECTION], publicArgs);
};
export const streamCollectionEditField = async (context, user, collectionId, input) => {
  const filtersItem = input.find((item) => item.key === 'filters');
  if (filtersItem?.value) {
    // our stix matching is currently limited, we need to validate the input filters
    validateFilterGroupForStixMatch(JSON.parse(filtersItem.value));
  }

  const finalInput = input.map(({ key, value }) => {
    const item = { key, value };
    if (key === authorizedMembers.name) {
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
    context_data: { id: collectionId, entity_type: ENTITY_TYPE_STREAM_COLLECTION, input },
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
    context_data: { id: collectionId, entity_type: ENTITY_TYPE_STREAM_COLLECTION, input: deleted },
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

// Stream consumer monitoring
export const getStreamCollectionConsumers = async (collectionId) => {
  // getConsumersForCollection is now async and reads from Redis (all instances)
  const consumers = await getConsumersForCollection(collectionId);
  if (consumers.length === 0) {
    return [];
  }
  const streamInfo = await fetchStreamInfo();
  const productionRate = await fetchStreamProductionRate();
  const streamHeadTimestamp = parseInt(streamInfo.lastEventId.split('-')[0], 10);
  const streamStartTimestamp = parseInt(streamInfo.firstEventId.split('-')[0], 10);

  return consumers.map((consumer) => {
    const consumerTimestamp = consumer.lastEventId
      ? parseInt(consumer.lastEventId.split('-')[0], 10)
      : 0;
    // Rates come pre-computed from Redis (flushed periodically by the owning instance)
    const { deliveryRate, processingRate, resolutionRate } = consumer;

    // Time lag: how far behind the consumer is from the stream head (in seconds)
    const timeLagMs = consumerTimestamp > 0 ? streamHeadTimestamp - consumerTimestamp : 0;
    const timeLag = timeLagMs / 1000;

    // Buffer: how far the consumer is from the oldest event in the stream
    const bufferMs = consumerTimestamp > 0 ? consumerTimestamp - streamStartTimestamp : 0;

    // Estimated time to out of depth:
    // If the consumer is falling behind (productionRate > processingRate), compute
    // how long until the buffer is exhausted and trimming catches up to the consumer.
    let estimatedOutOfDepth = null;
    if (consumerTimestamp > 0 && consumerTimestamp < streamStartTimestamp) {
      // Consumer is already out of depth
      estimatedOutOfDepth = 0;
    } else if (processingRate > 0 && productionRate > processingRate) {
      const netLagRate = productionRate - processingRate;
      // buffer in seconds / net lag rate gives estimated seconds to out of depth
      const bufferSeconds = bufferMs / 1000;
      if (netLagRate > 0 && bufferSeconds > 0) {
        estimatedOutOfDepth = bufferSeconds / netLagRate;
      }
    }
    // If consumer is keeping up (processingRate >= productionRate), estimatedOutOfDepth stays null

    return {
      connectionId: consumer.connectionId,
      userId: consumer.userId,
      userEmail: consumer.userEmail,
      connectedAt: consumer.connectedAt,
      lastEventId: consumer.lastEventId || '',
      lastEventDate: consumerTimestamp > 0 ? utcDate(consumerTimestamp).toISOString() : null,
      streamProductionRate: Math.round(productionRate * 100) / 100,
      consumerDeliveryRate: Math.round(deliveryRate * 100) / 100,
      consumerProcessingRate: Math.round(processingRate * 100) / 100,
      consumerResolutionRate: Math.round(resolutionRate * 100) / 100,
      timeLag: Math.round(timeLag * 100) / 100,
      estimatedOutOfDepth: estimatedOutOfDepth !== null
        ? Math.round(estimatedOutOfDepth * 100) / 100
        : null,
    };
  });
};
