import {
  createStatusTemplate,
  findAll,
  findAllTemplates,
  findById,
  findTemplateById,
  statusTemplateDelete,
  statusTemplateEditField
} from '../domain/status';
import type { Resolvers } from '../generated/graphql';

const statusResolvers: Resolvers = {
  Query: {
    statusTemplate: (_, { id }, context) => findTemplateById(context, context.user, id),
    statusTemplates: (_, args, context) => findAllTemplates(context, context.user, args),
    status: (_, { id }, context) => findById(context, context.user, id),
    statuses: (_, args, context) => findAll(context, context.user, args),
  },
  Status: {
    template: (current, _, context) => findTemplateById(context, context.user, current.template_id),
  },
  Mutation: {
    statusTemplateAdd: (_, { input }, context) => createStatusTemplate(context, context.user, input),
    statusTemplateDelete: (_, { id }, context) => statusTemplateDelete(context, context.user, id),
    statusTemplateFieldPatch: (_, { id, input }, context) => statusTemplateEditField(context, context.user, id, input),
  },
};

export default statusResolvers;
