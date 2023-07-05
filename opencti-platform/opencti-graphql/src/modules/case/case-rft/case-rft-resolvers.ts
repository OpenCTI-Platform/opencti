import type { Resolvers } from '../../../generated/graphql';
import { buildRefRelationKey } from '../../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING, RELATION_OBJECT_PARTICIPANT } from '../../../schema/stixRefRelationship';
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
  CaseRftsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    assigneeTo: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    participant: buildRefRelationKey(RELATION_OBJECT_PARTICIPANT),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    creator: 'creator_id',
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
