import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixDomain,
  stixDomainDelete,
  findAll,
  findById,
  search,
  stixDomainEditContext,
  stixDomainEditField,
  stixDomainAddRelation,
  stixDomainDeleteRelation,
  stixDomainCleanContext
} from '../domain/stixDomain';
import { pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const stixDomainResolvers = {
  Query: {
    stixDomain: auth((_, { id }) => findById(id)),
    identities: auth((_, args) => {
      if (args.search && args.search.length > 0) {
        return search(args);
      }
      return findAll(args);
    })
  },
  StixDomain: {
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
    stixDomainEdit: auth((_, { id }, { user }) => ({
      delete: () => stixDomainDelete(id),
      fieldPatch: ({ input }) => stixDomainEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEditContext(user, id, input),
      relationAdd: ({ input }) => stixDomainAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainDeleteRelation(user, id, relationId)
    })),
    stixDomainAdd: auth((_, { input }, { user }) => addStixDomain(user, input))
  },
  Subscription: {
    stixDomain: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        stixDomainEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.StixDomain.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixDomainCleanContext(user, id);
        });
      })
    }
  }
};

export default stixDomainResolvers;
