import { findById, findAll, attributeUpdate, attributeDelete, addAttribute } from '../domain/attribute';

const attributeResolvers = {
  Query: {
    attribute: (_, { id }) => findById(id),
    attributes: (_, args) => findAll(args),
  },
  Mutation: {
    attributeEdit: (_, { id }) => ({
      delete: () => attributeDelete(id),
      update: ({ input }) => attributeUpdate(id, input),
    }),
    attributeAdd: (_, { input }) => addAttribute(input),
  },
};

export default attributeResolvers;
