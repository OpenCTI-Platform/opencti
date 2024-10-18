import { $$asyncIterator } from 'iterall';
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

/**
 * @returns {Promise<AsyncIterable<any>>}
 */
const withCancel = (asyncIterator, onCancel) => {
  const updatedAsyncIterator = {
    return() {
      onCancel();
      return asyncIterator.return();
    },
    next() {
      return asyncIterator.next();
    },
    throw(error) {
      return asyncIterator.throw(error);
    },
  };
  // noinspection JSValidateTypes
  return { [$$asyncIterator]: () => updatedAsyncIterator };
};

/**
 * @returns {Promise<AsyncIterable<any>>}
 */
export const subscribeToUserEvents = async (context, topics) => {
  const asyncIterator = pubSubAsyncIterator(topics);
  const filtering = withFilter(() => asyncIterator, (payload) => {
    if (!payload) {
      // When disconnected, an empty payload is dispatched.
      return false;
    }
    return [payload.instance.user_id, payload.instance.id].includes(context.user.id);
  })();
  return {
    [Symbol.asyncIterator]() {
      return filtering;
    }
  };
};

/**
 * @returns {Promise<AsyncIterable<any>>}
 */
export const subscribeToAiEvents = async (context, id, topics) => {
  const asyncIterator = pubSubAsyncIterator(topics);
  const filtering = withFilter(() => asyncIterator, (payload) => {
    if (!payload) {
      // When disconnected, an empty payload is dispatched.
      return false;
    }
    return payload.user.id === context.user.id && payload.instance.bus_id === id;
  })();
  return {
    [Symbol.asyncIterator]() {
      return filtering;
    }
  };
};

/**
 * @returns {Promise<AsyncIterable<any>>}
 */
export const subscribeToInstanceEvents = async (parent, context, id, topics, opts = {}) => {
  const { preFn, cleanFn, notifySelf = false, type } = opts;
  if (preFn) preFn();
  const item = await internalLoadById(context, context.user, id, { baseData: true, type });
  if (!item) throw ForbiddenAccess('You are not allowed to listen this.');
  const filtering = withFilter(
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
    [Symbol.asyncIterator]() {
      return filtering;
    }
  };
};

/**
 * @returns {Promise<AsyncIterable<any>>}
 */
export const subscribeToPlatformSettingsEvents = async (context) => {
  const asyncIterator = pubSubAsyncIterator(BUS_TOPICS[ENTITY_TYPE_SETTINGS].EDIT_TOPIC);
  const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const filtering = withFilter(() => asyncIterator, (payload) => {
    const oldMessages = getMessagesFilteredByRecipients(context.user, settings);
    const newMessages = getMessagesFilteredByRecipients(context.user, payload.instance);
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
    [Symbol.asyncIterator]() {
      return filtering;
    }
  };
};
