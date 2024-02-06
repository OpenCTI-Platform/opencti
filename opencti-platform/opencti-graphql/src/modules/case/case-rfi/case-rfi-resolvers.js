import { buildRefRelationKey } from '../../../schema/general';
import { RELATION_OBJECT_ASSIGNEE } from '../../../schema/stixRefRelationship';
import { stixDomainObjectDelete } from '../../../domain/stixDomainObject';
import { addCaseRfi, caseRfiContainsStixObjectOrStixRelationship, findAll, findById } from './case-rfi-domain';
const caseRfiResolvers = {
    Query: {
        caseRfi: (_, { id }, context) => findById(context, context.user, id),
        caseRfis: (_, args, context) => findAll(context, context.user, args),
        caseRfiContainsStixObjectOrStixRelationship: (_, args, context) => {
            return caseRfiContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
        },
    },
    CaseRfisOrdering: {
        creator: 'creator_id',
        objectAssignee: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    },
    Mutation: {
        caseRfiAdd: (_, { input }, context) => {
            return addCaseRfi(context, context.user, input);
        },
        caseRfiDelete: (_, { id }, context) => {
            return stixDomainObjectDelete(context, context.user, id);
        },
    }
};
export default caseRfiResolvers;
