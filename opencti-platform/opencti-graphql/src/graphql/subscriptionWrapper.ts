import { withFilter } from 'graphql-subscriptions';
import * as R from 'ramda';
import { pubSubAsyncIterator } from '../database/redis';
import { internalLoadById } from '../database/middleware-loader';
import { ForbiddenAccess } from '../config/errors';
import { BUS_TOPICS } from '../config/conf';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { getEntityFromCache } from '../database/cache';
import { isUserCanAccessStoreElement, isUserHasCapability, isUserInPlatformOrganization, SYSTEM_USER } from '../utils/access';
import { getMessagesFilteredByRecipients } from '../domain/settings';
import { isUserAccountValid, resolveUserByIdFromCache } from '../modules/user/user-domain';
import { computeLoaders } from '../http/httpAuthenticatedContext';
import { withoutWithheldHits } from '../utils/withheldElements';
import type { BasicStoreSettings, BasicStoreSettingsMessage } from '../types/settings';

/**
 * Whether the subscriber may still receive an event of an instance it listens
 * to. The user of a subscription context is a snapshot taken when the socket
 * opened, with the account state, capabilities, groups, markings and
 * organizations of that moment, and so is its membership of the platform
 * organization: all are read again for every event, so an account locked or
 * expired since then, a capability removed or an access lost stops the events.
 * An event that passes is resolved with that current identity.
 */
export const canSubscriberStillAccess = async (context: any, instance: any, requiredCapabilities: string[] = []): Promise<boolean> => {
  try {
    const subscriber = context?.user?.id ? await resolveUserByIdFromCache(context, context.user.id) : undefined;
    if (!subscriber) return false;
    const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    if (!isUserAccountValid(subscriber, settings)) return false;
    if (!requiredCapabilities.every((capability) => isUserHasCapability(subscriber, capability))) return false;
    const user = { ...context.user, ...subscriber, origin: context.user.origin };
    const userInsidePlatformOrganization = isUserInPlatformOrganization(subscriber, settings);
    const subscriberContext = { ...context, user, user_inside_platform_organization: userInsidePlatformOrganization };
    if (!await isUserCanAccessStoreElement(subscriberContext, user, instance)) return false;
    if ((await withoutWithheldHits(subscriberContext, user, [instance])).length === 0) return false;
    Object.assign(context, { user, user_inside_platform_organization: userInsidePlatformOrganization, batch: computeLoaders(context, user) });
    return true;
  } catch {
    // A throw here closes the socket (4500) and orphans the redis sub.
    return false;
  }
};

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
    // A throw here closes the socket (4500) and orphans the redis sub; guard all fields.
    if (!payload || !payload.instance) {
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
    // A throw here closes the socket (4500) and orphans the redis sub; guard all fields.
    if (!payload || !payload.user || !payload.instance) {
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
    preFn?: () => void;
    cleanFn?: () => void;
    notifySelf?: boolean;
    type?: string | string[];
    // Check the subscriber's access on every event, for an instance whose markings can change while it is listened to.
    recheckAccess?: boolean;
    // The capabilities the subscription requires, checked again on every event with recheckAccess.
    requiredCapabilities?: string[];
  } = {},
): Promise<AsyncIterable<any>> => {
  const { preFn, cleanFn, notifySelf = false, type, recheckAccess = false, requiredCapabilities = [] } = opts;
  if (preFn) preFn();
  const item = await internalLoadById(context, context.user, id, { baseData: true, type });
  if (!item) throw ForbiddenAccess('You are not allowed to listen this.');
  const isEventOfInstance = (payload: any) => {
    // A throw here closes the socket (4500) and orphans the redis sub; guard before deref.
    if (!payload || !payload.instance) {
      return false;
    }
    if (!notifySelf) {
      // Only this branch needs the event user; a user-less (system) event must still reach notifySelf subs.
      if (!payload.user) {
        return false;
      }
      return payload.user.id !== context.user.id && payload.instance.id === id;
    }
    return payload.instance.id === id;
  };
  const filtering = await withFilter(
    () => pubSubAsyncIterator(topics),
    async (payload) => {
      if (!isEventOfInstance(payload)) {
        return false;
      }
      return !recheckAccess || canSubscriberStillAccess(context, payload.instance, requiredCapabilities);
    },
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
    // A throw here closes the socket (4500) and orphans the redis sub; guard all fields.
    if (!payload || !payload.instance) {
      return false;
    }
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
