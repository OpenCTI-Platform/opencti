import type { Resolvers } from '../../generated/graphql';
import { getAuthorizedMembers } from '../../utils/authorizedMembers';
import { addNotifier, getNotifierConnector, notifierDelete, notifierEdit, notifierGet, notifiersFind, testNotifier, usableNotifiers } from './notifier-domain';

const notifierResolvers: Resolvers = {
  Query: {
    notifier: (_, { id }, context) => notifierGet(context, context.user, id),
    notifiers: (_, args, context) => notifiersFind(context, context.user, args),
    notificationNotifiers: (_, __, context) => usableNotifiers(context, context.user),
    notifierTest: (_, { input }, context) => testNotifier(context, context.user, input),
  },
  Notifier: {
    notifier_connector: (notifier, _, context) => getNotifierConnector(context, context.user, notifier.notifier_connector_id),
    authorized_members: (notifier, _, context) => getAuthorizedMembers(context, context.user, notifier),
  },
  NotifierOrdering: {
    connector: 'notifier_connector_id',
  },
  Mutation: {
    notifierAdd: (_, { input }, context) => addNotifier(context, context.user, input),
    notifierDelete: (_, { id }, context) => notifierDelete(context, context.user, id),
    notifierFieldPatch: (_, { id, input }, context) => notifierEdit(context, context.user, id, input),
  },
};

export default notifierResolvers;
