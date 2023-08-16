import type { Resolvers } from '../../generated/graphql';
import { playbookAdd, playbookDelete, playbookEdit, findById, findAll, availableComponents } from './playbook-domain';
import { isNotEmptyField } from '../../database/utils';

const playbookResolvers: Resolvers = {
  Query: {
    playbook: (_, { id }, context) => findById(context, context.user, id),
    playbooks: (_, args, context) => findAll(context, context.user, args),
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    playbookComponents: () => availableComponents(),
  },
  PlaybookComponent: {
    configuration_schema: (current) => (isNotEmptyField(current.configuration_schema) ? JSON.stringify(current.configuration_schema) : '{}')
  },
  Mutation: {
    playbookAdd: (_, { input }, context) => playbookAdd(context, context.user, input),
    playbookDelete: (_, { id }, context) => playbookDelete(context, context.user, id),
    playbookFieldPatch: (_, { id, input }, context) => playbookEdit(context, context.user, id, input),
  },
};

export default playbookResolvers;
