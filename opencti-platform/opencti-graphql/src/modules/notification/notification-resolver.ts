import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../../config/conf';
import { pubSubAsyncIterator } from '../../database/redis';
import type { Resolvers } from '../../generated/graphql';
import { TriggerType } from '../../generated/graphql';
import { getUserAccessRight, isDirectAdministrator } from '../../utils/access';
import { getNotifiers } from '../notifier/notifier-domain';
import {
  addTrigger,
  addTriggerActivity,
  getTriggerRecipients,
  myNotificationsFind,
  myUnreadNotificationsCount,
  notificationDelete,
  notificationEditRead,
  notificationGet,
  notificationsFind,
  triggerActivityEdit,
  triggerDelete,
  triggerEdit,
  triggerGet,
  triggersActivityFind,
  triggersGet,
  triggersKnowledgeFind,
} from './notification-domain';
import {
  type BasicStoreEntityLiveTrigger,
  type BasicStoreEntityTrigger,
  ENTITY_TYPE_NOTIFICATION,
  NOTIFICATION_NUMBER
} from './notification-types';

const notificationResolvers: Resolvers = {
  Query: {
    // Knowledge trigger
    triggerKnowledge: (_, { id }, context) => triggerGet(context, context.user, id),
    triggersKnowledge: (_, args, context) => triggersKnowledgeFind(context, context.user, args),
    // Activity trigger
    triggerActivity: (_, { id }, context) => triggerGet(context, context.user, id),
    triggersActivity: (_, args, context) => triggersActivityFind(context, context.user, args),
    // Notifications
    notification: (_, { id }, context) => notificationGet(context, context.user, id),
    notifications: (_, args, context) => notificationsFind(context, context.user, args),
    myNotifications: (_, args, context) => myNotificationsFind(context, context.user, args),
    myUnreadNotificationsCount: (_, __, context) => myUnreadNotificationsCount(context, context.user),
  },
  Trigger: {
    triggers: (trigger, _, context) => triggersGet(context, context.user, trigger.trigger_ids), // For Digest
    recipients: (trigger, _, context) => getTriggerRecipients(context, context.user, trigger),
    isDirectAdministrator: (trigger, _, context) => isDirectAdministrator(context.user, trigger),
    currentUserAccessRight: (trigger, _, context) => getUserAccessRight(context.user, trigger),
    notifiers: (trigger, _, context) => getNotifiers(context, context.user, trigger.notifiers),
  },
  TriggerFilter: {
    user_ids: 'authorized_members.id',
    group_ids: 'authorized_members.id',
    organization_ids: 'authorized_members.id',
  },
  Mutation: {
    // Knowledge trigger
    triggerKnowledgeFieldPatch: (_, { id, input }, context) => triggerEdit(context, context.user, id, input),
    triggerKnowledgeDelete: (_, { id }, context) => triggerDelete(context, context.user, id),
    triggerKnowledgeLiveAdd: (_, { input }, context) => addTrigger(context, context.user, input, TriggerType.Live),
    triggerKnowledgeDigestAdd: (_, { input }, context) => addTrigger(context, context.user, input, TriggerType.Digest),
    // Activity trigger
    triggerActivityFieldPatch: (_, { id, input }, context) => triggerActivityEdit(context, context.user, id, input),
    triggerActivityDelete: (_, { id }, context) => triggerDelete(context, context.user, id),
    triggerActivityLiveAdd: (_, { input }, context) => addTriggerActivity(context, context.user, input, TriggerType.Live),
    triggerActivityDigestAdd: (_, { input }, context) => addTriggerActivity(context, context.user, input, TriggerType.Digest),
    // Notification
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
        return {
          [Symbol.asyncIterator]() {
            return filtering;
          }
        };
      },
    },
    notification: {
      resolve: /* istanbul ignore next */ (payload: any) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, __, context) => {
        const asyncIterator = pubSubAsyncIterator(BUS_TOPICS[ENTITY_TYPE_NOTIFICATION].ADDED_TOPIC);
        const filtering = withFilter(() => asyncIterator, (payload) => {
          return payload && payload.instance.user_id === context.user.id;
        })();
        return {
          [Symbol.asyncIterator]() {
            return filtering;
          }
        };
      },
    },
  },
};

export default notificationResolvers;
