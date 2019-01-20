import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixDomainEntity,
  stixDomainEntityDelete,
  findAll,
  findById,
  search,
  stixDomainEntityEditContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityCleanContext
} from '../domain/stixDomainEntity';
import { pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const stixDomainEntityResolvers = {
  Query: {
    stixDomainEntity: auth((_, { id }) => findById(id)),
    stixDomainEntities: auth((_, args) => {
      if (args.search && args.search.length > 0) {
        return search(args);
      }
      return findAll(args);
    })
  },
  StixDomainEntity: {
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
    stixDomainEntityEdit: auth((_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    })),
    stixDomainEntityAdd: auth((_, { input }, { user }) => addStixDomainEntity(user, input))
  },
  Subscription: {
    stixDomainEntity: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        stixDomainEntityEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixDomainEntityCleanContext(user, id);
        });
      })
    }
  }
};

export default stixDomainEntityResolvers;
