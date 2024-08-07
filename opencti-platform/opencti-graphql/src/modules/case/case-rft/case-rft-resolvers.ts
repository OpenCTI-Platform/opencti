import type { Resolvers } from '../../../generated/graphql';
import { buildRefRelationKey } from '../../../schema/general';
import { RELATION_OBJECT_ASSIGNEE } from '../../../schema/stixRefRelationship';
import { stixDomainObjectDelete } from '../../../domain/stixDomainObject';
import { addCaseRft, caseRftContainsStixObjectOrStixRelationship, caseRftEditAuthorizedMembers, findAll, findById } from './case-rft-domain';
import { getAuthorizedMembers } from '../../../utils/authorizedMembers';
import { getUserAccessRight } from '../../../utils/access';

const caseRftResolvers: Resolvers = {
  Query: {
    caseRft: (_, { id }, context) => findById(context, context.user, id),
    caseRfts: (_, args, context) => findAll(context, context.user, args),
    caseRftContainsStixObjectOrStixRelationship: (_, args, context) => {
      return caseRftContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  CaseRft: {
    authorized_members: (caseRft, _, context) => getAuthorizedMembers(context, context.user, caseRft),
    currentUserAccessRight: (caseRft, _, context) => getUserAccessRight(context.user, caseRft),
  },
  CaseRftsOrdering: {
    creator: 'creator_id',
    objectAssignee: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
  },
  Mutation: {
    caseRftAdd: (_, { input }, context) => {
      return addCaseRft(context, context.user, input);
    },
    caseRftDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
    caseRftEditAuthorizedMembers: (_, { id, input }, context) => {
      return caseRftEditAuthorizedMembers(context, context.user, id, input);
    },
  }
};

export default caseRftResolvers;
