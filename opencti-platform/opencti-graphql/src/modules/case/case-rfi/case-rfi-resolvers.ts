import type { Resolvers } from '../../../generated/graphql';
import { buildRefRelationKey } from '../../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING, RELATION_OBJECT_PARTICIPANT } from '../../../schema/stixRefRelationship';
import { stixDomainObjectDelete } from '../../../domain/stixDomainObject';
import { addCaseRfi, caseRfiContainsStixObjectOrStixRelationship, findAll, findById } from './case-rfi-domain';

const caseRfiResolvers: Resolvers = {
  Query: {
    caseRfi: (_, { id }, context) => findById(context, context.user, id),
    caseRfis: (_, args, context) => findAll(context, context.user, args),
    caseRfiContainsStixObjectOrStixRelationship: (_, args, context) => {
      return caseRfiContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  CaseRfisFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    assigneeTo: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    participant: buildRefRelationKey(RELATION_OBJECT_PARTICIPANT),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    creator: 'creator_id',
  },
  CaseRfisOrdering: {
    creator: 'creator_id',
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
