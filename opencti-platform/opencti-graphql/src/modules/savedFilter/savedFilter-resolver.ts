import type { Resolvers } from '../../generated/graphql';
import { addSavedFilter, deleteSavedFilter, fieldPatchSavedFilter, findSaveFilterPaginated } from './savedFilter-domain';

const savedFilterResolver: Resolvers = {
  Query: {
    savedFilters: (_, args, context) => findSaveFilterPaginated(context, context.user, args),
  },
  Mutation: {
    savedFilterAdd: (_, { input }, context) => {
      return addSavedFilter(context, context.user, input);
    },
    savedFilterDelete: (_, { id }, context) => {
      return deleteSavedFilter(context, context.user, id);
    },
    savedFilterFieldPatch: (_, args, context) => {
      return fieldPatchSavedFilter(context, context.user, args);
    }
  },
};

export default savedFilterResolver;
