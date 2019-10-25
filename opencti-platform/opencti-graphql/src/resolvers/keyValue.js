import {
  findByKey,
  keyValueDelete,
  keyValueUpdate,
  addKeyValue
} from '../domain/keyValue';

const keyValueResolvers = {
  Query: {
    keyValue: (_, { key }) => findByKey(key)
  },
  Mutation: {
    keyValueEdit: (_, { key }) => ({
      delete: () => keyValueDelete(key),
      update: ({ value }) => keyValueUpdate(key, value)
    }),
    keyValueAdd: (_, { input }) => addKeyValue(input)
  }
};

export default keyValueResolvers;
