import type { Resolvers } from '../../../generated/graphql';
import { findTaskTemplatePaginated, findById, taskTemplateAdd, taskTemplateDelete, taskTemplateEdit } from './task-template-domain';

const taskTemplateResolvers: Resolvers = {
  Query: {
    taskTemplate: (_, { id }, context) => findById(context, context.user, id),
    taskTemplates: (_, args, context) => findTaskTemplatePaginated(context, context.user, args)
  },
  Mutation: {
    taskTemplateAdd: (_, { input }, context) => taskTemplateAdd(context, context.user, input),
    taskTemplateDelete: (_, { id }, context) => taskTemplateDelete(context, context.user, id),
    taskTemplateFieldPatch: (_, { id, input }, context) => taskTemplateEdit(context, context.user, id, input),
  },
};

export default taskTemplateResolvers;
