import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addCountry,
  countryDelete,
  findAll,
  findById,
  markingDefinitions,
  countryEditContext,
  countryEditField,
  countryAddRelation,
  countryDeleteRelation,
  countryCleanContext
} from '../domain/country';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const countryResolvers = {
  Query: {
    country: auth((_, { id }) => findById(id)),
    countries: auth((_, args) => findAll(args))
  },
  Country: {
    markingDefinitions: (country, args) =>
      markingDefinitions(country.id, args),
    editContext: auth(country => fetchEditContext(country.id))
  },
  Mutation: {
    countryEdit: auth((_, { id }, { user }) => ({
      delete: () => countryDelete(id),
      fieldPatch: ({ input }) => countryEditField(user, id, input),
      contextPatch: ({ input }) => countryEditContext(user, id, input),
      relationAdd: ({ input }) => countryAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        countryDeleteRelation(user, id, relationId)
    })),
    countryAdd: auth((_, { input }, { user }) => addCountry(user, input))
  },
  Subscription: {
    country: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        countryEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Country.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          countryCleanContext(user, id);
        });
      })
    }
  }
};

export default countryResolvers;
