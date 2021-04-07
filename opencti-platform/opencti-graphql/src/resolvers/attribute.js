import { findById, findAll, attributeEditField, attributeDelete, addAttribute } from '../domain/attribute';

const attributeResolvers = {
  Query: {
    attribute: (_, { id }, { user }) => findById(user, id),
    attributes: (_, args, { user }) => findAll(user, args),
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
