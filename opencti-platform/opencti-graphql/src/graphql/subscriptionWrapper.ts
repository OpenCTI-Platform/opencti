import { withFilter } from 'graphql-subscriptions';
import * as R from 'ramda';
import { pubSubAsyncIterator } from '../database/redis';
import { internalLoadById } from '../database/middleware-loader';
import { ForbiddenAccess } from '../config/errors';
import { BUS_TOPICS } from '../config/conf';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { getEntityFromCache } from '../database/cache';
import { SYSTEM_USER } from '../utils/access';
import { getMessagesFilteredByRecipients } from '../domain/settings';
import type { BasicStoreSettingsMessage } from '../types/settings';

const withCancel = (asyncIterator: AsyncIterableIterator<any>, onCancel: () => void): AsyncIterable<any> => {
  const returnFn = asyncIterator.return;
  const throwFn = asyncIterator.throw;
  const updatedAsyncIterator = {
    next: () => asyncIterator.next(),
    return: returnFn ? () => {
      onCancel();
      return returnFn();
    } : undefined,
    throw: throwFn ? (error: Error) => throwFn(error) : undefined,
  };
  return { [Symbol.asyncIterator]: () => updatedAsyncIterator };
};

export const subscribeToUserEvents = async (context: any, topics: string | string[]): Promise<AsyncIterable<any>> => {
  const asyncIterator = pubSubAsyncIterator(topics);
  const filtering = await withFilter(() => asyncIterator, (payload) => {
    if (!payload) {
      // When disconnected, an empty payload is dispatched.
      return false;
    }
    return [payload.instance.user_id, payload.instance.id].includes(context.user.id);
  })();
  return {
    [Symbol.asyncIterator]: () => filtering,
  };
};

export const subscribeToAiEvents = async (context: any, id: string, topics: string | string[]): Promise<AsyncIterable<any>> => {
  const asyncIterator = pubSubAsyncIterator(topics);
  const filtering = await withFilter(() => asyncIterator, (payload) => {
    if (!payload) {
      // When disconnected, an empty payload is dispatched.
      return false;
    }
    return payload.user.id === context.user.id && payload.instance.bus_id === id;
  })();
  return {
    [Symbol.asyncIterator]: () => filtering,
  };
};

export const subscribeToInstanceEvents = async (
  parent: any,
  context: any,
  id: string,
  topics: string | string[],
  opts: {
    preFn?: () => void,
    cleanFn?: () => void,
    notifySelf? : boolean,
    type?: string | string[],
  } = {}
): Promise<AsyncIterable<any>> => {
  const { preFn, cleanFn, notifySelf = false, type } = opts;
  if (preFn) preFn();
  const item = await internalLoadById(context, context.user, id, { baseData: true, type });
  if (!item) throw ForbiddenAccess('You are not allowed to listen this.');
  const filtering = await withFilter(
    () => pubSubAsyncIterator(topics),
    (payload) => {
      if (!payload) {
        // When disconnected, an empty payload is dispatched.
        return false;
      }
      if (!notifySelf) {
        return payload.user.id !== context.user.id && payload.instance.id === id;
      }
      return payload.instance.id === id;
    }
  )(parent, { id }, context);
  if (cleanFn) {
    return withCancel(filtering, () => {
      cleanFn();
    });
  }
  return {
    [Symbol.asyncIterator]: () => filtering,
  };
};

export const subscribeToPlatformSettingsEvents = async (context: any): Promise<AsyncIterable<any>> => {
  const asyncIterator = pubSubAsyncIterator(BUS_TOPICS[ENTITY_TYPE_SETTINGS].EDIT_TOPIC);
  const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const filtering = await withFilter(() => asyncIterator, (payload) => {
    const oldMessages: BasicStoreSettingsMessage[] = getMessagesFilteredByRecipients(context.user, settings);
    const newMessages: BasicStoreSettingsMessage[] = getMessagesFilteredByRecipients(context.user, payload.instance);
    // If removed and was activated
    const removedMessage = R.difference(oldMessages, newMessages);
    if (removedMessage.length === 1 && removedMessage[0].activated) {
      return true;
    }
    return newMessages.some((nm) => {
      const find = oldMessages.find((om) => nm.id === om.id);
      // If existing, change when property activated change OR when message change and status is activated
      if (find) {
        return (nm.activated !== find.activated) || (nm.activated && nm.message !== find.message);
      }
      // If new, change when message is activated
      return nm.activated;
    });
  })();
  return {
    [Symbol.asyncIterator]: () => filtering,
  };
};
