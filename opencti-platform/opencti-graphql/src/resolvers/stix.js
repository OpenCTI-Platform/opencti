import { stixDelete } from '../domain/stix';
import { stixLoadByIdStringify } from '../database/middleware';

const stixResolvers = {
  Query: {
    stix: async (_, { id }, { user }) => stixLoadByIdStringify(user, id)
  },
  Mutation: {
    stixEdit: (_, { id }, { user }) => ({
      delete: () => stixDelete(user, id),
    }),
  },
};

export default stixResolvers;
