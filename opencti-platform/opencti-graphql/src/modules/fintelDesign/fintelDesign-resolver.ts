import type { Resolvers } from '../../generated/graphql';
import { addFintelDesign, findFintelDesignPaginated, findById, fintelDesignDelete, fintelDesignEditContext, fintelDesignEditField } from './fintelDesign-domain';

const fintelDesignResolvers: Resolvers = {
  Query: {
    fintelDesign: (_, { id }, context) => findById(context, context.user, id),
    fintelDesigns: (_, args, context) => {
      return findFintelDesignPaginated(context, context.user, args);
    },
  },
  Mutation: {
    fintelDesignAdd: (_, { input }, context) => {
      return addFintelDesign(context, context.user, input);
    },
    fintelDesignDelete: (_, { id }, context) => {
      return fintelDesignDelete(context, context.user, id);
    },
    fintelDesignFieldPatch: (_, args, context) => {
      return fintelDesignEditField(context, context.user, args);
    },
    fintelDesignContextPatch: (_, { id, input }, context) => {
      return fintelDesignEditContext(context, context.user, id, input);
    },
  },
};

export default fintelDesignResolvers;
