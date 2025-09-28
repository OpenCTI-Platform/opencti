import { getRuntimeAttributeValues, getSchemaAttributeNames, getSchemaAttributes } from '../domain/attribute';

const attributeResolvers = {
  Query: {
    runtimeAttributes: (_, args, context) => getRuntimeAttributeValues(context, context.user, args),
    schemaAttributeNames: (_, { elementType }) => getSchemaAttributeNames(elementType),
    schemaAttributes: (_) => getSchemaAttributes(),
  },
};

export default attributeResolvers;
