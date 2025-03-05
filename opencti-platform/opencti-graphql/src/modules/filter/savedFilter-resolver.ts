import type { Resolvers } from '../../generated/graphql';
import { addSavedFilter, deleteSavedFilter, findAll } from './savedFilter-domain';

const savedFilterResolver: Resolvers = {
  Query: {
    savedFilters: (_, args, context) => findAll(context, context.user, args),
  },
  Mutation: {
    savedFilterAdd: (_, { input }, context) => {
      return addSavedFilter(context, context.user, input);
    },
    savedFilterDelete: (_, { id }, context) => {
      return deleteSavedFilter(context, context.user, id);
    },
  },
};

export default savedFilterResolver;
