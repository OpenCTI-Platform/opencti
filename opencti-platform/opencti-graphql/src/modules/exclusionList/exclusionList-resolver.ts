import type { Resolvers } from '../../generated/graphql';
import { findById, findAll, addExclusionListFile, deleteExclusionList, fieldPatchExclusionList, getCacheStatus } from './exclusionList-domain';

const exclusionListResolver: Resolvers = {
  Query: {
    exclusionList: (_, { id }, context) => findById(context, context.user, id),
    exclusionLists: (_, args, context) => findAll(context, context.user, args),
    exclusionListCacheStatus: () => getCacheStatus(),
  },
  Mutation: {
    exclusionListFileAdd: (_, { input }, context) => {
      return addExclusionListFile(context, context.user, input);
    },
    exclusionListFieldPatch: (_, args, context) => {
      return fieldPatchExclusionList(context, context.user, args);
    },
    exclusionListDelete: (_, { id }, context) => {
      return deleteExclusionList(context, context.user, id);
    },
  },
};

export default exclusionListResolver;
