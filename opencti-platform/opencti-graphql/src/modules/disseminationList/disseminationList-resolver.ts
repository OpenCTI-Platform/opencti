import type { Resolvers } from '../../generated/graphql';
import { sendToDisseminationList } from './disseminationList-domain';

const disseminationListResolvers: Resolvers = {
  Query: {
    // disseminationList: (_, { id }, context) => findById(context, context.user, id),
    // disseminationLists: (_, args, context) => findAll(context, context.user, args),
  },
  DisseminationList: {},
  Mutation: {
    // disseminationListAdd: (_, { input }, context) => {
    //   return addDisseminationList(context, context.user, input);
    // },
    // disseminationListDelete: (_, { id }, context) => {
    //   return deleteDisseminationList(context, context.user, id);
    // },
    // disseminationListFieldPatch: (_, { id, input }, context) => {
    //   return fieldPatchDisseminationList(context, context.user, id, input);
    // },
    disseminationListSend: (_, { input }, context) => {
      return sendToDisseminationList(context, context.user, input);
    }
  }
};

export default disseminationListResolvers;
