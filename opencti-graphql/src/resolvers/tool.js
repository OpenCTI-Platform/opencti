import {
  addTool,
  toolDelete,
  findAll,
  findById
} from '../domain/tool';
import {
  createdByRef,
  killChainPhases,
  markingDefinitions,
  reports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';
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
    stixRelations: (threatActor, args) => stixRelations(threatActor.id, args),
    editContext: auth(tool => fetchEditContext(tool.id))
  },
  Mutation: {
    toolEdit: auth((_, { id }, { user }) => ({
      delete: () => toolDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    })),
    toolAdd: auth((_, { input }, { user }) => addTool(user, input))
  }
};

export default toolResolvers;
