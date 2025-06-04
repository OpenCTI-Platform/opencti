import type { Resolvers } from '../../generated/graphql';
import { pirFlagElement, deletePir, findAll, findById, pirAdd, pirUnflagElement, updatePir } from './pir-domain';
import { batchLoader } from '../../database/middleware';
import { batchCreators } from '../../domain/user';
import { batchMarkingDefinitions } from '../../domain/stixCoreObject';

const creatorsLoader = batchLoader(batchCreators);
const markingDefinitionsLoader = batchLoader(batchMarkingDefinitions);

const pirResolvers: Resolvers = {
  Query: {
    pir: (_, { id }, context) => findById(context, context.user, id),
    pirs: (_, args, context) => findAll(context, context.user, args),
  },
  Pir: {
    creators: (pir, _, context) => creatorsLoader.load(pir.creator_id, context, context.user),
    objectMarking: (pir, _, context) => markingDefinitionsLoader.load(pir, context, context.user),
  },
  Mutation: {
    pirAdd: (_, { input }, context) => pirAdd(context, context.user, input),
    pirFieldPatch: (_, { id, input }, context) => updatePir(context, context.user, id, input),
    pirDelete: (_, { id }, context) => deletePir(context, context.user, id),
    pirFlagElement: (_, { id, input }, context) => pirFlagElement(context, context.user, id, input),
    pirUnflagElement: (_, { id, input }, context) => pirUnflagElement(context, context.user, id, input),
  }
};

export default pirResolvers;
