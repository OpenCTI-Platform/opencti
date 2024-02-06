import { caseTemplateAdd, caseTemplateAddRelation, caseTemplateDelete, caseTemplateDeleteRelation, caseTemplateEdit, findAll, findById, taskTemplatesPaginated } from './case-template-domain';
const caseTemplateResolvers = {
    Query: {
        caseTemplate: (_, { id }, context) => findById(context, context.user, id),
        caseTemplates: (_, args, context) => findAll(context, context.user, args),
    },
    CaseTemplate: {
        tasks: (current, args, context) => taskTemplatesPaginated(context, context.user, current.id, args),
    },
    Mutation: {
        caseTemplateAdd: (_, { input }, context) => caseTemplateAdd(context, context.user, input),
        caseTemplateDelete: (_, { id }, context) => caseTemplateDelete(context, context.user, id),
        caseTemplateFieldPatch: (_, { id, input }, context) => caseTemplateEdit(context, context.user, id, input),
        caseTemplateRelationAdd: (_, { id, input }, context) => {
            return caseTemplateAddRelation(context, context.user, id, input);
        },
        caseTemplateRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
            return caseTemplateDeleteRelation(context, context.user, id, toId, relationshipType);
        },
    },
};
export default caseTemplateResolvers;
