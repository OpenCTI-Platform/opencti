import type { Resolvers } from '../../../generated/graphql';
import { buildRefRelationKey } from '../../../schema/general';
import { RELATION_OBJECT_ASSIGNEE } from '../../../schema/stixRefRelationship';
import { stixDomainObjectDelete } from '../../../domain/stixDomainObject';
import { addCaseRfi, caseRfiContainsStixObjectOrStixRelationship, caseRfiEditAuthorizedMembers, findAll, findById } from './case-rfi-domain';
import { getAuthorizedMembers } from '../../../utils/authorizedMembers';
import { getUserAccessRight } from '../../../utils/access';

const caseRfiResolvers: Resolvers = {
  Query: {
    caseRfi: (_, { id }, context) => findById(context, context.user, id),
    caseRfis: (_, args, context) => findAll(context, context.user, args),
    caseRfiContainsStixObjectOrStixRelationship: (_, args, context) => {
      return caseRfiContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  CaseRfi: {
    authorized_members: (caseRfi, _, context) => getAuthorizedMembers(context, context.user, caseRfi),
    currentUserAccessRight: (caseRfi, _, context) => getUserAccessRight(context.user, caseRfi),
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
    caseRfiEditAuthorizedMembers: (_, { id, input }, context) => {
      return caseRfiEditAuthorizedMembers(context, context.user, id, input);
    },
  }
};

export default caseRfiResolvers;
