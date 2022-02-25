import {
  findById,
  findAll,
  createUserSubscription,
  userSubscriptionDelete,
  userSubscriptionEditField,
  userSubscriptionEditContext,
  userSubscriptionCleanContext,
} from '../domain/userSubscription';
import { internalLoadById } from '../database/middleware';

const userSubscriptionResolvers = {
  Query: {
    userSubscription: (_, { id }, { user }) => findById(user, id),
    userSubscriptions: (_, args, { user }) => findAll(user, args),
  },
  UserSubscription: {
    user: (current, _, { user }) => internalLoadById(user, current.user_id),
    entities: (current, _, { user }) => (current.entities_ids && current.entities_ids.length > 0
      ? Promise.all(current.entities_ids.map((e) => internalLoadById(user, e)))
      : null),
  },
  Mutation: {
    userSubscriptionAdd: (_, { input }, { user }) => createUserSubscription(user, input),
    userSubscriptionEdit: (_, { id }, { user }) => ({
      delete: () => userSubscriptionDelete(user, id),
      fieldPatch: ({ input }) => userSubscriptionEditField(user, id, input),
      contextPatch: ({ input }) => userSubscriptionEditContext(user, id, input),
      contextClean: () => userSubscriptionCleanContext(user, id),
    }),
  },
};

export default userSubscriptionResolvers;
