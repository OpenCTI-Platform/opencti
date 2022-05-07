import { stixDelete } from '../domain/stix';
import { stixLoadById } from '../database/middleware';

const stixResolvers = {
  Query: {
    stix: async (_, { id }, { user }) => {
      const data = await stixLoadById(user, id);
      return JSON.stringify(data);
    }
  },
  Mutation: {
    stixEdit: (_, { id }, { user }) => ({
      delete: () => stixDelete(user, id),
    }),
  },
};

export default stixResolvers;
