import { stixDelete } from '../domain/stix';
import { stixLoadByIdStringify } from '../database/middleware';
import { connectorsForEnrichment } from '../database/repository';

const stixResolvers = {
  Query: {
    stix: async (_, { id }, { user }) => stixLoadByIdStringify(user, id),
    enrichmentConnectors: (_, { type }, { user }) => connectorsForEnrichment(user, type, true),
  },
  Mutation: {
    stixEdit: (_, { id }, { user }) => ({
      delete: () => stixDelete(user, id),
    }),
  },
};

export default stixResolvers;
