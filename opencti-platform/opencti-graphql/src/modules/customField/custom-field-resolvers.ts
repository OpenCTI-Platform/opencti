import type { Resolvers } from '../../generated/graphql';
import {
  customFieldDefinitionAdd,
  customFieldDefinitionAddEntityType,
  customFieldDefinitionDelete,
  customFieldDefinitionEdit,
  customFieldDefinitionRemoveEntityType,
  findById,
  findCustomFieldDefinitionsPaginated,
} from './custom-field-domain';

const customFieldResolvers: Resolvers = {
  Query: {
    customFieldDefinition: (_: unknown, { id }: { id: string }, context: any) => findById(context, context.user, id),
    customFieldDefinitions: (_: unknown, args: any, context: any) => findCustomFieldDefinitionsPaginated(context, context.user, args),
  },
  Mutation: {
    customFieldDefinitionAdd: (_: unknown, { input }: { input: any }, context: any) => customFieldDefinitionAdd(context, context.user, input),
    customFieldDefinitionDelete: (_: unknown, { id }: { id: string }, context: any) => customFieldDefinitionDelete(context, context.user, id),
    customFieldDefinitionFieldPatch: (_: unknown, { id, input }: { id: string; input: any }, context: any) => customFieldDefinitionEdit(context, context.user, id, input),
    customFieldDefinitionAddEntityType: (_: unknown, { id, entityType }: { id: string; entityType: string }, context: any) => customFieldDefinitionAddEntityType(context, context.user, id, entityType),
    customFieldDefinitionRemoveEntityType: (_: unknown, { id, entityType }: { id: string; entityType: string }, context: any) => customFieldDefinitionRemoveEntityType(context, context.user, id, entityType),
  },
};

export default customFieldResolvers;
