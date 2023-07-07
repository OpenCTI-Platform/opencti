import { withFilter } from 'graphql-subscriptions';
import type { Resolvers } from '../../generated/graphql';
import { TriggerType } from '../../generated/graphql';
import {
  addTrigger,
  myNotificationsFind,
  myUnreadNotificationsCount,
  notificationDelete,
  notificationEditRead,
  notificationGet,
  notificationsFind,
  resolvedInstanceFiltersGet,
  triggerDelete,
  triggerEdit,
  triggerGet,
  triggersFind,
  triggersGet,
} from './notification-domain';
import { pubSubAsyncIterator } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import {
  BasicStoreEntityLiveTrigger,
  BasicStoreEntityTrigger,
  ENTITY_TYPE_NOTIFICATION,
  NOTIFICATION_NUMBER
} from './notification-types';
import { getUserAccessRight } from '../../utils/access';

const notificationResolvers: Resolvers = {
  Query: {
    // Triggers
    trigger: (_, { id }, context) => triggerGet(context, context.user, id),
    triggers: (_, args, context) => triggersFind(context, context.user, args),
    // Notifications
    notification: (_, { id }, context) => notificationGet(context, context.user, id),
    notifications: (_, args, context) => notificationsFind(context, context.user, args),
    myNotifications: (_, args, context) => myNotificationsFind(context, context.user, args),
    myUnreadNotificationsCount: (_, __, context) => myUnreadNotificationsCount(context, context.user),
  },
  Trigger: {
    triggers: (trigger, _, context) => triggersGet(context, context.user, trigger.trigger_ids),
    currentUserAccessRight: (trigger, _, context) => getUserAccessRight(context.user, trigger),
    resolved_instance_filters: (trigger: BasicStoreEntityLiveTrigger | BasicStoreEntityTrigger, _, context) => resolvedInstanceFiltersGet(context, context.user, trigger),
  },
  TriggerFilter: {
    user_ids: 'authorized_members.id',
    group_ids: 'authorized_members.id',
    organization_ids: 'authorized_members.id',
  },
  Mutation: {
    triggerFieldPatch: (_, { id, input }, context) => triggerEdit(context, context.user, id, input),
    triggerDelete: (_, { id }, context) => triggerDelete(context, context.user, id),
    triggerLiveAdd: (_, { input }, context) => addTrigger(context, context.user, input, TriggerType.Live),
    triggerDigestAdd: (_, { input }, context) => addTrigger(context, context.user, input, TriggerType.Digest),
    notificationDelete: (_, { id }, context) => notificationDelete(context, context.user, id),
    notificationMarkRead: (_, { id, read }, context) => notificationEditRead(context, context.user, id, read),
  },
  Subscription: {
    notificationsNumber: {
      resolve: /* istanbul ignore next */ (payload: any) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, __, context) => {
        const asyncIterator = pubSubAsyncIterator(BUS_TOPICS[NOTIFICATION_NUMBER].EDIT_TOPIC);
        const filtering = withFilter(() => asyncIterator, (payload) => {
          return payload && payload.instance.user_id === context.user.id;
        })();
        return { [Symbol.asyncIterator]() { return filtering; } };
      },
    },
    notification: {
      resolve: /* istanbul ignore next */ (payload: any) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, __, context) => {
        const asyncIterator = pubSubAsyncIterator(BUS_TOPICS[ENTITY_TYPE_NOTIFICATION].ADDED_TOPIC);
        const filtering = withFilter(() => asyncIterator, (payload) => {
          return payload && payload.instance.user_id === context.user.id;
        })();
        return { [Symbol.asyncIterator]() { return filtering; } };
      },
    },
  },
};

export default notificationResolvers;
