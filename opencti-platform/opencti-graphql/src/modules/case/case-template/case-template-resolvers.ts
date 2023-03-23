import type { Resolvers } from '../../../generated/graphql';
import { caseTemplateAdd, caseTemplateDelete, caseTemplateEdit, findAll, findById } from './case-template-domain';
import { containersObjectsOfObject } from '../../../domain/container';
import { ENTITY_TYPE_CONTAINER_CASE_TASK } from '../case-task/case-task-types';

const caseTemplateResolvers: Resolvers = {
  Query: {
    caseTemplate: (_, { id }, context) => findById(context, context.user, id),
    caseTemplates: (_, args, context) => findAll(context, context.user, args),
  },
  CaseTemplate: {
    tasks: (current, _, context) => containersObjectsOfObject(context, context.user, { id: current.id, types: [ENTITY_TYPE_CONTAINER_CASE_TASK] }),
  },
  Mutation: {
    caseTemplateAdd: (_, { input }, context) => caseTemplateAdd(context, context.user, input),
    caseTemplateDelete: (_, { id }, context) => caseTemplateDelete(context, context.user, id),
    caseTemplateFieldPatch: (_, { id, input }, context) => caseTemplateEdit(context, context.user, id, input),
  },
};

export default caseTemplateResolvers;
