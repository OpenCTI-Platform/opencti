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
} from '../domain/tool';
import { fetchEditContext } from '../database/redis';
import { auth } from './wrapper';

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
  }
};

export default toolResolvers;
