import type { Resolvers } from '../../generated/graphql';
import { addCase, findAll, findById } from './case-domain';
import { buildRefRelationKey } from '../../schema/general';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT_ASSIGNEE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING
} from '../../schema/stixMetaRelationship';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete, stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';

const caseResolvers: Resolvers = {
  Query: {
    case: (_, { id }, context) => findById(context, context.user, id),
    cases: (_, args, context) => findAll(context, context.user, args),
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
    caseAdd: (_, { input }, context) => {
      return addCase(context, context.user, input);
    },
    caseDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
    caseFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    caseRelationAdd: (_, { id, input }, context) => {
      return stixDomainObjectAddRelation(context, context.user, id, input);
    },
    caseRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
    caseContextPatch: (_, { id, input }, context) => {
      return stixDomainObjectEditContext(context, context.user, id, input);
    },
    caseContextClean: (_, { id }, context) => {
      return stixDomainObjectCleanContext(context, context.user, id);
    },
  }
};

export default caseResolvers;
