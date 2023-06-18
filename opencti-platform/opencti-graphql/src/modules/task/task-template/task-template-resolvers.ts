import type { Resolvers } from '../../../generated/graphql';
import { buildRefRelationKey } from '../../../schema/general';
import {
  taskTemplateAdd,
  taskTemplateDelete,
  taskTemplateEdit,
  findAll,
  findById
} from './task-template-domain';
import { TEMPLATE_TASK_RELATION } from '../../case/case-template/case-template-types';

const taskTemplateResolvers: Resolvers = {
  Query: {
    taskTemplate: (_, { id }, context) => findById(context, context.user, id),
    taskTemplates: (_, args, context) => findAll(context, context.user, args)
  },
  TaskTemplatesFilter: {
    taskContains: buildRefRelationKey(TEMPLATE_TASK_RELATION)
  },
  Mutation: {
    taskTemplateAdd: (_, { input }, context) => taskTemplateAdd(context, context.user, input),
    taskTemplateDelete: (_, { id }, context) => taskTemplateDelete(context, context.user, id),
    taskTemplateFieldPatch: (_, { id, input }, context) => taskTemplateEdit(context, context.user, id, input),
  },
};

export default taskTemplateResolvers;
