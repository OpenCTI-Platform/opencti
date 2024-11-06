import type { Resolvers } from '../../generated/graphql';
import { findById, findAll, addExclusionListContent, addExclusionListFile, deleteExclusionList } from './exclusionList-domain';

const exclusionListResolver: Resolvers = {
  Query: {
    exclusionList: (_, { id }, context) => findById(context, context.user, id),
    exclusionLists: (_, args, context) => findAll(context, context.user, args),
  },
  Mutation: {
    exclusionListContentAdd: (_, { input }, context) => {
      return addExclusionListContent(context, context.user, input);
    },
    exclusionListFileAdd: (_, { input }, context) => {
      return addExclusionListFile(context, context.user, input);
    },
    exclusionListDelete: (_, { id }, context) => {
      return deleteExclusionList(context, context.user, id);
    },
  },
};

export default exclusionListResolver;
