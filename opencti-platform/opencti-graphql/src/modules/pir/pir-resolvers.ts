import type { Resolvers } from '../../generated/graphql';
import { pirFlagElement, deletePir, findAll, findById, pirAdd, pirUnflagElement, updatePir } from './pir-domain';

const pirResolvers: Resolvers = {
  Query: {
    pir: (_, { id }, context) => findById(context, context.user, id),
    pirs: (_, args, context) => findAll(context, context.user, args),
  },
  Pir: {
    creators: (pir, _, context) => context.batch.creatorsBatchLoader.load(pir.creator_id),
    objectMarking: (pir, _, context) => context.batch.markingsBatchLoader.load(pir),
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
