import {
  findAll,
  attributeUpdate,
  attributeDelete,
  addAttribute
} from '../domain/attribute';

const attributeResolvers = {
  Query: {
    attributes: (_, args) => findAll(args)
  },
  Mutation: {
    attributeEdit: (_, { type, value }) => ({
      delete: () => attributeDelete(type, value),
      update: ({ newValue }) => attributeUpdate(type, value, newValue)
    }),
    attributeAdd: (_, { input }, { user }) => addAttribute(user, input)
  }
};

export default attributeResolvers;
