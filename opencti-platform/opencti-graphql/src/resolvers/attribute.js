import { getRuntimeAttributeValues, attributeEditField, getSchemaAttributeValues } from '../domain/attribute';

const attributeResolvers = {
  Query: {
    runtimeAttributes: (_, args, context) => getRuntimeAttributeValues(context, context.user, args),
    schemaAttributes: (_, { elementType }) => getSchemaAttributeValues(elementType),
  },
  Mutation: {
    runtimeAttributeEdit: (_, input, context) => attributeEditField(context, input),
  },
};

export default attributeResolvers;
