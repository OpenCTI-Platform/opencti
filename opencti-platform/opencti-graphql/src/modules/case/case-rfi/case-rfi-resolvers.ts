import type { Resolvers } from '../../../generated/graphql';
import { buildRefRelationKey } from '../../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../../../schema/stixRefRelationship';
import { stixDomainObjectAddRelation, stixDomainObjectCleanContext, stixDomainObjectDelete, stixDomainObjectDeleteRelation, stixDomainObjectEditContext, stixDomainObjectEditField } from '../../../domain/stixDomainObject';
import {
  addCaseRfi,
  caseRfiContainsStixObjectOrStixRelationship,
  findAll,
  findById
} from './case-rfi-domain';

const caseRfiResolvers: Resolvers = {
  Query: {
    caseRfi: (_, { id }, context) => findById(context, context.user, id),
    caseRfis: (_, args, context) => findAll(context, context.user, args),
    caseRfiContainsStixObjectOrStixRelationship: (_, args, context) => {
      return caseRfiContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  CasesFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    assigneeTo: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    creator: 'creator_id',
  },
  CasesOrdering: {
    creator: 'creator_id',
  },
  Mutation: {
    caseRfiAdd: (_, { input }, context) => {
      return addCaseRfi(context, context.user, input);
    },
    caseRfiDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
    caseRfiRelationAdd: (_, { id, input }, context) => {
      return stixDomainObjectAddRelation(context, context.user, id, input);
    },
    caseRfiRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
    caseRfiFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    caseRfiContextPatch: (_, { id, input }, context) => {
      return stixDomainObjectEditContext(context, context.user, id, input);
    },
    caseRfiContextClean: (_, { id }, context) => {
      return stixDomainObjectCleanContext(context, context.user, id);
    },
  }
};

export default caseRfiResolvers;
