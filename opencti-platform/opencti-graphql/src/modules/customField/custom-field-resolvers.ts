import type { Resolvers } from '../../generated/graphql';
import {
  customFieldDefinitionAdd,
  customFieldDefinitionAddEntityType,
  customFieldDefinitionDelete,
  customFieldDefinitionEdit,
  customFieldDefinitionRemoveEntityType,
  customFieldDefinitionUpdateEntityType,
  findById,
  findCustomFieldDefinitionsPaginated,
} from './custom-field-domain';

const customFieldResolvers: Resolvers = {
  Query: {
    customFieldDefinition: (_, { id }, context) => findById(context, context.user, id),
    customFieldDefinitions: (_, args, context) => findCustomFieldDefinitionsPaginated(context, context.user, args),
  },
  Mutation: {
    customFieldDefinitionAdd: (_, { input }, context) => customFieldDefinitionAdd(context, context.user, input),
    customFieldDefinitionDelete: (_, { id }, context) => customFieldDefinitionDelete(context, context.user, id),
    customFieldDefinitionFieldPatch: (_, { id, input }, context) => customFieldDefinitionEdit(context, context.user, id, input),
    customFieldDefinitionAddEntityType: (_, { id, entityType, mandatory, default_value }, context) => (
      customFieldDefinitionAddEntityType(context, context.user, id, entityType, mandatory, default_value)
    ),
    customFieldDefinitionUpdateEntityType: (_, { id, entityType, mandatory, default_value }, context) => (
      customFieldDefinitionUpdateEntityType(context, context.user, id, entityType, mandatory, default_value)
    ),
    customFieldDefinitionRemoveEntityType: (_, { id, entityType }, context) => customFieldDefinitionRemoveEntityType(context, context.user, id, entityType),
  },
};

export default customFieldResolvers;
