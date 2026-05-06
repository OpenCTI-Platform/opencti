import type { Resolvers } from '../../generated/graphql';
import { customFieldAdd, customFieldDelete, customFieldEdit, findById, findCustomFieldsPaginated } from './custom-field-domain';

const customFieldResolvers: Resolvers = {
  Query: {
    customField: (_: unknown, { id }: { id: string }, context: any) => findById(context, context.user, id),
    customFields: (_: unknown, args: any, context: any) => findCustomFieldsPaginated(context, context.user, args),
  },
  Mutation: {
    customFieldAdd: (_: unknown, { input }: { input: any }, context: any) => customFieldAdd(context, context.user, input),
    customFieldDelete: (_: unknown, { id }: { id: string }, context: any) => customFieldDelete(context, context.user, id),
    customFieldFieldPatch: (_: unknown, { id, input }: { id: string; input: any }, context: any) => customFieldEdit(context, context.user, id, input),
  },
};

export default customFieldResolvers;
