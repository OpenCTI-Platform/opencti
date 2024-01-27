import { addTool, findAll, findById } from '../domain/tool';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { loadThroughDenormalized } from './stix';
import { INPUT_KILLCHAIN } from '../schema/general';

const toolResolvers = {
  Query: {
    tool: (_, { id }, context) => findById(context, context.user, id),
    tools: (_, args, context) => findAll(context, context.user, args),
  },
  Tool: {
    killChainPhases: (tool, _, context) => loadThroughDenormalized(context, context.user, tool, INPUT_KILLCHAIN),
  },
  Mutation: {
    toolEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    toolAdd: (_, { input }, context) => addTool(context, context.user, input),
  },
};

export default toolResolvers;
