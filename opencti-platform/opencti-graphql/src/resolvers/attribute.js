import { getRuntimeAttributeValues, getSchemaAttributeValues } from '../domain/attribute';

const attributeResolvers = {
  Query: {
    runtimeAttributes: (_, args, context) => getRuntimeAttributeValues(context, context.user, args),
    schemaAttributes: (_, { elementType }) => getSchemaAttributeValues(elementType),
  },
};

export default attributeResolvers;
