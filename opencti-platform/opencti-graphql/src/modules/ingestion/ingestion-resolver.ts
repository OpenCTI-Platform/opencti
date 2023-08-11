import { addIngestion, findAllPaginated, findById, ingestionDelete, ingestionEditField, } from './ingestion-domain';
import type { Resolvers } from '../../generated/graphql';

const ingestionResolvers: Resolvers = {
  Query: {
    ingestion: (_, { id }, context) => findById(context, context.user, id),
    ingestions: (_, args, context) => findAllPaginated(context, context.user, args),
  },
  Mutation: {
    ingestionAdd: (_, { input }, context) => {
      return addIngestion(context, context.user, input);
    },
    ingestionDelete: (_, { id }, context) => {
      return ingestionDelete(context, context.user, id);
    },
    ingestionFieldPatch: (_, { id, input }, context) => {
      return ingestionEditField(context, context.user, id, input);
    },
  },
};

export default ingestionResolvers;
