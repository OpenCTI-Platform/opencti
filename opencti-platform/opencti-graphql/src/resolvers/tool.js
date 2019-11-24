import { addTool, findAll, findById } from '../domain/tool';
import {
  killChainPhases,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';

const toolResolvers = {
  Query: {
    tool: (_, { id }) => findById(id),
    tools: (_, args) => findAll(args)
  },
  ToolsOrdering: {
    markingDefinitions: 'object_marking_refs.definition',
    tags: 'tagged.value'
  },
  Tool: {
    killChainPhases: (tool, args) => killChainPhases(tool.id, args)
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
