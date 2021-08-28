import { stixDelete } from '../domain/stix';

const stixResolvers = {
  Mutation: {
    stixEdit: (_, { id }, { user }) => ({
      delete: () => stixDelete(user, id),
    }),
  },
};

export default stixResolvers;
