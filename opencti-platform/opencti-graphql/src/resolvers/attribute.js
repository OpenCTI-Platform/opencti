import { getRuntimeAttributeValues, getSchemaAttributeNames } from '../domain/attribute';

const attributeResolvers = {
  Query: {
    runtimeAttributes: (_, args, context) => getRuntimeAttributeValues(context, context.user, args),
    schemaAttributeNames: (_, { elementType }) => getSchemaAttributeNames(elementType),
  },
};

export default attributeResolvers;
