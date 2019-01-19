import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addIdentity,
  identityDelete,
  findAll,
  findById,
  search,
  identityEditContext,
  identityEditField,
  identityAddRelation,
  identityDeleteRelation,
  identityCleanContext
} from '../domain/identity';
import { pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const identityResolvers = {
  Query: {
    identity: auth((_, { id }) => findById(id)),
    identities: auth((_, args) => {
      if (args.search && args.search.length > 0) {
        return search(args);
      }
      return findAll(args);
    })
  },
  Identity: {
    __resolveType(obj) {
      if (obj.type) {
        return obj.type.replace(/(?:^|-)(\w)/g, (matches, letter) =>
          letter.toUpperCase()
        );
      }
      return 'Unknown';
    }
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
