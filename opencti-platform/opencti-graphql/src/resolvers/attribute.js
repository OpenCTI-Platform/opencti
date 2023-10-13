import { getRuntimeAttributeValues, getSchemaAttributeNames, getSchemaAttributes } from '../domain/attribute';

const attributeResolvers = {
  Query: {
    runtimeAttributes: (_, args, context) => getRuntimeAttributeValues(context, context.user, args),
    schemaAttributeNames: (_, { elementType }) => getSchemaAttributeNames(elementType),
    schemaAttributes: (_, { entityType }, context) => getSchemaAttributes(context, entityType),
  },
};

export default attributeResolvers;
