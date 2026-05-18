import type { Resolvers } from '../../generated/graphql';
import {
  addSavedFilter,
  deleteSavedFilter,
  fieldPatchSavedFilter,
  findSaveFilterPaginated,
  getCurrentUserAccessRight,
  savedFilterEditAuthorizedMembers,
} from './savedFilter-domain';
import { getAuthorizedMembers } from '../../utils/authorizedMembers';

const savedFilterResolver: Resolvers = {
  Query: {
    savedFilters: (_, args, context) => findSaveFilterPaginated(context, context.user, args),
  },
  SavedFilter: {
    authorizedMembers: (savedFilter, _, context) => getAuthorizedMembers(context, context.user, savedFilter),
    currentUserAccessRight: (savedFilter, _, context) => getCurrentUserAccessRight(context, context.user, savedFilter),
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
    },
    savedFilterEditAuthorizedMembers: (_, { id, input }, context) => {
      return savedFilterEditAuthorizedMembers(context, context.user, id, input);
    },
  },
};

export default savedFilterResolver;
