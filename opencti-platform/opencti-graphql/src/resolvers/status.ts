import {
  createStatusTemplate,
  findAll,
  findAllTemplates,
  findById,
  findTemplateById,
  statusTemplateCleanContext,
  statusTemplateDelete,
  statusTemplateEditContext,
  statusTemplateEditField,
  statusTemplateUsagesNumber
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
  StatusTemplate: {
    usages: (current, _, context) => statusTemplateUsagesNumber(context, context.user, current.id),
  },
  Mutation: {
    statusTemplateAdd: (_, { input }, context) => createStatusTemplate(context, context.user, input),
    statusTemplateDelete: (_, { id }, context) => statusTemplateDelete(context, context.user, id),
    statusTemplateFieldPatch: (_, { id, input }, context) => statusTemplateEditField(context, context.user, id, input),
    statusTemplateContextPatch: (_, { id, input }, context) => statusTemplateEditContext(context, context.user, id, input),
    statusTemplateContextClean: (_, { id }, context) => statusTemplateCleanContext(context, context.user, id),
  },
};

export default statusResolvers;
