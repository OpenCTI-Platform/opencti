import { getRuntimeAttributeValues, attributeEditField, getSchemaAttributeValues } from '../domain/attribute';

const attributeResolvers = {
  Query: {
    runtimeAttributes: (_, args, { user }) => getRuntimeAttributeValues(user, args),
    schemaAttributes: (_, { elementType }) => getSchemaAttributeValues(elementType),
  },
  Mutation: {
    runtimeAttributeEdit: (_, input) => attributeEditField(input),
  },
};

export default attributeResolvers;
