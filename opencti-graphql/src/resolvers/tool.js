import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addTool,
  toolDelete,
  findAll,
  findById,
  createdByRef,
  markingDefinitions,
  killChainPhases,
  reports,
  toolEditContext,
  toolEditField,
  toolAddRelation,
  toolDeleteRelation,
  toolCleanContext
} from '../domain/tool';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const toolResolvers = {
  Query: {
    tool: auth((_, { id }) => findById(id)),
    tools: auth((_, args) => findAll(args))
  },
  Tool: {
    createdByRef: (tool, args) => createdByRef(tool.id, args),
    markingDefinitions: (tool, args) => markingDefinitions(tool.id, args),
    killChainPhases: (tool, args) => killChainPhases(tool.id, args),
    reports: (tool, args) => reports(tool.id, args),
    editContext: auth(tool => fetchEditContext(tool.id))
  },
  Mutation: {
    toolEdit: auth((_, { id }, { user }) => ({
      delete: () => toolDelete(id),
      fieldPatch: ({ input }) => toolEditField(user, id, input),
      contextPatch: ({ input }) => toolEditContext(user, id, input),
      relationAdd: ({ input }) => toolAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        toolDeleteRelation(user, id, relationId)
    })),
    toolAdd: auth((_, { input }, { user }) => addTool(user, input))
  },
  Subscription: {
    tool: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        toolEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Tool.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          toolCleanContext(user, id);
        });
      })
    }
  }
};

export default toolResolvers;
