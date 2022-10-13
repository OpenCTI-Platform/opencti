import {
  findById,
  findAll,
  createUserSubscription,
  userSubscriptionDelete,
  userSubscriptionEditField,
  userSubscriptionEditContext,
  userSubscriptionCleanContext,
} from '../domain/userSubscription';
import { internalLoadById } from '../database/middleware-loader';

const userSubscriptionResolvers = {
  Query: {
    userSubscription: (_, { id }, context) => findById(context, context.user, id),
    userSubscriptions: (_, args, context) => findAll(context, context.user, args),
  },
  UserSubscription: {
    user: (current, _, context) => internalLoadById(context, context.user, current.user_id),
    entities: (current, _, context) => (current.entities_ids && current.entities_ids.length > 0
      ? Promise.all(current.entities_ids.map((e) => internalLoadById(context, context.user, e)))
      : null),
  },
  Mutation: {
    userSubscriptionAdd: (_, { input }, context) => createUserSubscription(context, context.user, input),
    userSubscriptionEdit: (_, { id }, context) => ({
      delete: () => userSubscriptionDelete(context, context.user, id),
      fieldPatch: ({ input }) => userSubscriptionEditField(context, context.user, id, input),
      contextPatch: ({ input }) => userSubscriptionEditContext(context, context.user, id, input),
      contextClean: () => userSubscriptionCleanContext(context, context.user, id),
    }),
  },
};

export default userSubscriptionResolvers;
