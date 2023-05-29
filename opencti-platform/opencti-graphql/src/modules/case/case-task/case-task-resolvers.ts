import type { Resolvers } from '../../../generated/graphql';
import { buildRefRelationKey } from '../../../schema/general';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT,
  RELATION_OBJECT_ASSIGNEE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING
} from '../../../schema/stixRefRelationship';
import {
  caseTaskAdd,
  caseTaskAddRelation,
  caseTaskDeleteRelation,
  caseTaskContainsStixObjectOrStixRelationship,
  caseTaskDelete,
  caseTaskEdit,
  findAll,
  findById
} from './case-task-domain';

const caseTaskResolvers: Resolvers = {
  Query: {
    caseTask: (_, { id }, context) => findById(context, context.user, id),
    caseTasks: (_, args, context) => findAll(context, context.user, args),
    caseTaskContainsStixObjectOrStixRelationship: (_, args, context) => {
      return caseTaskContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  CaseTasksFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    assigneeTo: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    objectContains: buildRefRelationKey(RELATION_OBJECT, '*')
  },
  Mutation: {
    caseTaskAdd: (_, { input }, context) => caseTaskAdd(context, context.user, input),
    caseTaskDelete: (_, { id }, context) => caseTaskDelete(context, context.user, id),
    caseTaskFieldPatch: (_, { id, input }, context) => caseTaskEdit(context, context.user, id, input),
    caseTaskRelationAdd: (_, { id, input }, context) => {
      return caseTaskAddRelation(context, context.user, id, input);
    },
    caseTaskRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return caseTaskDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  },
};

export default caseTaskResolvers;
