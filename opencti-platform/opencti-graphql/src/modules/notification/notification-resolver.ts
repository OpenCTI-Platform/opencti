import { BUS_TOPICS } from '../../config/conf';
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
  triggersFind,
  triggersGet,
  triggersKnowledgeCount,
  triggersKnowledgeFind,
} from './notification-domain';
import { ENTITY_TYPE_NOTIFICATION, NOTIFICATION_NUMBER } from './notification-types';
import { subscribeToUserEvents } from '../../graphql/subscriptionWrapper';

const notificationResolvers: Resolvers = {
  Query: {
    // Knowledge trigger
    triggerKnowledge: (_, { id }, context) => triggerGet(context, context.user, id),
    triggersKnowledge: (_, args, context) => triggersKnowledgeFind(context, context.user, args),
    triggersKnowledgeCount: (_, args, context) => triggersKnowledgeCount(context, args),
    // Activity trigger
    triggerActivity: (_, { id }, context) => triggerGet(context, context.user, id),
    triggersActivity: (_, args, context) => triggersActivityFind(context, context.user, args),
    // All triggers : knowledge & activity if user has the right capability
    triggers: (_, args, context) => triggersFind(context, context.user, args),
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
      resolve: /* v8 ignore next */ (payload: any) => payload.instance,
      subscribe: /* v8 ignore next */ (_, __, context) => {
        const bus = BUS_TOPICS[NOTIFICATION_NUMBER];
        return subscribeToUserEvents(context, [bus.EDIT_TOPIC]);
      },
    },
    notification: {
      resolve: /* v8 ignore next */ (payload: any) => payload.instance,
      subscribe: /* v8 ignore next */ (_, __, context) => {
        const bus = BUS_TOPICS[ENTITY_TYPE_NOTIFICATION];
        return subscribeToUserEvents(context, [bus.EDIT_TOPIC]);
      },
    },
  },
};

export default notificationResolvers;
