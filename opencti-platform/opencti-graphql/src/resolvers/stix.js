import { stixDelete } from '../domain/stix';
import { stixLoadByIdStringify } from '../database/middleware';
import { connectorsForEnrichment } from '../database/repository';

const stixResolvers = {
  Query: {
    stix: async (_, { id }, context) => stixLoadByIdStringify(context, context.user, id),
    enrichmentConnectors: (_, { type }, context) => connectorsForEnrichment(context, context.user, type, true),
  },
  Mutation: {
    stixEdit: (_, { id }, context) => ({
      delete: () => stixDelete(context, context.user, id),
    }),
  },
};

export default stixResolvers;
