import { addIngestion, findAllPaginated, findById, ingestionDelete, ingestionEditField, } from './ingestion-taxii-domain';
import type { Resolvers } from '../../generated/graphql';

const ingestionTaxiiResolvers: Resolvers = {
  Query: {
    taxiiIngestion: (_, { id }, context) => findById(context, context.user, id),
    taxiiIngestions: (_, args, context) => findAllPaginated(context, context.user, args),
  },
  Mutation: {
    taxiiIngestionAdd: (_, { input }, context) => {
      return addIngestion(context, context.user, input);
    },
    taxiiIngestionDelete: (_, { id }, context) => {
      return ingestionDelete(context, context.user, id);
    },
    taxiiIngestionFieldPatch: (_, { id, input }, context) => {
      return ingestionEditField(context, context.user, id, input);
    },
  },
};

export default ingestionTaxiiResolvers;
