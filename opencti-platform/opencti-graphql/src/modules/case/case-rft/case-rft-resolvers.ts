import type { Resolvers } from '../../../generated/graphql';
import { buildRefRelationKey } from '../../../schema/general';
import { RELATION_OBJECT_ASSIGNEE } from '../../../schema/stixRefRelationship';
import { stixDomainObjectDelete } from '../../../domain/stixDomainObject';
import { addCaseRft, caseRftContainsStixObjectOrStixRelationship, findAll, findById } from './case-rft-domain';

const caseRftResolvers: Resolvers = {
  Query: {
    caseRft: (_, { id }, context) => findById(context, context.user, id),
    caseRfts: (_, args, context) => findAll(context, context.user, args),
    caseRftContainsStixObjectOrStixRelationship: (_, args, context) => {
      return caseRftContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
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
  }
};

export default caseRftResolvers;
