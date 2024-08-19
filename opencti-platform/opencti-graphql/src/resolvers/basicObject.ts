import { findFiltersRepresentatives } from '../domain/basicObject';
import type { Resolvers } from '../generated/graphql';

const basicObjectResolvers: Resolvers = {
  Query: {
    filtersRepresentatives: (_, { filters }, context) => findFiltersRepresentatives(context, context.user, filters),
  }
};

export default basicObjectResolvers;
