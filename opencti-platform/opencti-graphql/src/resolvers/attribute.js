import { getRuntimeAttributeValues, getSchemaAttributeNames, getSchemaAttributes } from '../domain/attribute';

const attributeResolvers = {
  Query: {
    runtimeAttributes: (_, args, context) => getRuntimeAttributeValues(context, context.user, args),
    schemaAttributeNames: (_, { elementType }, context) => getSchemaAttributeNames(context, context.user, elementType),
    schemaAttributes: (_, args, context) => getSchemaAttributes(context, context.user),
  },
};

export default attributeResolvers;
