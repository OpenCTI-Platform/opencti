import type { Resolvers } from '../../generated/graphql';
import { findAll, findById, taskAdd, taskAddRelation, taskContainsStixObjectOrStixRelationship, taskDelete, taskDeleteRelation, taskEdit } from './task-domain';
import { loadThroughDenormalized } from '../../resolvers/stix';
import { INPUT_PARTICIPANT } from '../../schema/general';

const taskResolvers: Resolvers = {
  Query: {
    task: (_, { id }, context) => findById(context, context.user, id),
    tasks: (_, args, context) => findAll(context, context.user, args),
    taskContainsStixObjectOrStixRelationship: (_, args, context) => {
      return taskContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  Task: {
    objectParticipant: (container, _, context) => loadThroughDenormalized(context, context.user, container, INPUT_PARTICIPANT, { sortBy: 'user_email' }),
  },
  Mutation: {
    taskAdd: (_, { input }, context) => taskAdd(context, context.user, input),
    taskDelete: (_, { id }, context) => taskDelete(context, context.user, id),
    taskFieldPatch: (_, { id, input }, context) => taskEdit(context, context.user, id, input),
    taskRelationAdd: (_, { id, input }, context) => {
      return taskAddRelation(context, context.user, id, input);
    },
    taskRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return taskDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  },
};

export default taskResolvers;
