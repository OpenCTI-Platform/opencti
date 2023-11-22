import { getRuntimeAttributeValues, getSchemaAttributeNames } from '../domain/attribute';
import { getSchemaAttributes, getSchemaAttributesAll } from '../domain/attribute-details';

const attributeResolvers = {
  Query: {
    runtimeAttributes: (_, args, context) => getRuntimeAttributeValues(context, context.user, args),
    schemaAttributeNames: (_, { elementType }) => getSchemaAttributeNames(elementType),
    schemaAttributes: (_, { entityType }, context) => getSchemaAttributes(context, entityType),
    schemaAttributesAll: (_, { entityType }, context) => getSchemaAttributesAll(context, entityType),
  },
};

export default attributeResolvers;
