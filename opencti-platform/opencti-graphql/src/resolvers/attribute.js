import { findById, findAll, attributeEditField, attributeDelete, addAttribute } from '../domain/attribute';

const attributeResolvers = {
  Query: {
    attribute: (_, { id }) => findById(id),
    attributes: (_, args) => findAll(args),
  },
  Mutation: {
    attributeEdit: (_, { id }, { user }) => ({
      delete: () => attributeDelete(user, id),
      fieldPatch: ({ input }) => attributeEditField(user, id, input),
    }),
    attributeAdd: (_, { input }, { user }) => addAttribute(user, input),
  },
};

export default attributeResolvers;
