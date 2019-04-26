import { addTool, findAll, findById } from '../domain/tool';
import {
  createdByRef,
  killChainPhases,
  markingDefinitions,
  reports,
  exports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';

const toolResolvers = {
  Query: {
    tool: (_, { id }) => findById(id),
    tools: (_, args) => findAll(args)
  },
  Tool: {
    createdByRef: (tool, args) => createdByRef(tool.id, args),
    markingDefinitions: (tool, args) => markingDefinitions(tool.id, args),
    killChainPhases: (tool, args) => killChainPhases(tool.id, args),
    reports: (tool, args) => reports(tool.id, args),
    exports: (tool, args) => exports(tool.id, args),
    stixRelations: (threatActor, args) => stixRelations(threatActor.id, args),
    editContext: tool => fetchEditContext(tool.id)
  },
  Mutation: {
    toolEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    toolAdd: (_, { input }, { user }) => addTool(user, input)
  }
};

export default toolResolvers;
