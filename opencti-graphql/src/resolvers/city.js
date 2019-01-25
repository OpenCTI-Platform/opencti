import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addCity,
  cityDelete,
  findAll,
  findById,
  markingDefinitions,
  cityEditContext,
  cityEditField,
  cityAddRelation,
  cityDeleteRelation,
  cityCleanContext
} from '../domain/city';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const cityResolvers = {
  Query: {
    city: auth((_, { id }) => findById(id)),
    cities: auth((_, args) => findAll(args))
  },
  City: {
    markingDefinitions: (city, args) => markingDefinitions(city.id, args),
    editContext: auth(city => fetchEditContext(city.id))
  },
  Mutation: {
    cityEdit: auth((_, { id }, { user }) => ({
      delete: () => cityDelete(id),
      fieldPatch: ({ input }) => cityEditField(user, id, input),
      contextPatch: ({ input }) => cityEditContext(user, id, input),
      relationAdd: ({ input }) => cityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        cityDeleteRelation(user, id, relationId)
    })),
    cityAdd: auth((_, { input }, { user }) => addCity(user, input))
  },
  Subscription: {
    city: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        cityEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.City.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          cityCleanContext(user, id);
        });
      })
    }
  }
};

export default cityResolvers;
