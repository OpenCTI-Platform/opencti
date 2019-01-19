import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addIdentity,
  identityDelete,
  findAll,
  findById,
  markingDefinitions,
  identityEditContext,
  identityEditField,
  identityAddRelation,
  identityDeleteRelation,
  identityCleanContext
} from '../domain/identity';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const identityResolvers = {
  Query: {
    identity: auth((_, { id }) => findById(id)),
    identities: auth((_, args) => findAll(args))
  },
  Identity: {
    markingDefinitions: (identity, args) =>
      markingDefinitions(identity.id, args),
    editContext: auth(identity => fetchEditContext(identity.id))
  },
  Mutation: {
    identityEdit: auth((_, { id }, { user }) => ({
      delete: () => identityDelete(id),
      fieldPatch: ({ input }) => identityEditField(user, id, input),
      contextPatch: ({ input }) => identityEditContext(user, id, input),
      relationAdd: ({ input }) => identityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        identityDeleteRelation(user, id, relationId)
    })),
    identityAdd: auth((_, { input }, { user }) => addIdentity(user, input))
  },
  Subscription: {
    identity: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        identityEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Identity.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          identityCleanContext(user, id);
        });
      })
    }
  }
};

export default identityResolvers;
