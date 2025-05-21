import type { Resolvers } from '../../generated/graphql';
import { pirFlagElement, deletePir, findAll, findById, pirAdd, pirUnflagElement } from './pir-domain';
import { batchLoader } from '../../database/middleware';
import { batchCreators } from '../../domain/user';

const creatorsLoader = batchLoader(batchCreators);

const pirResolvers: Resolvers = {
  Query: {
    pir: (_, { id }, context) => findById(context, context.user, id),
    pirs: (_, args, context) => findAll(context, context.user, args),
  },
  Pir: {
    creators: (pir, _, context) => creatorsLoader.load(pir.creator_id, context, context.user),
  },
  Mutation: {
    pirAdd: (_, { input }, context) => pirAdd(context, context.user, input),
    pirDelete: (_, { id }, context) => deletePir(context, context.user, id),
    pirFlagElement: (_, { id, input }, context) => pirFlagElement(context, context.user, id, input),
    pirUnflagElement: (_, { id, input }, context) => pirUnflagElement(context, context.user, id, input),
  }
};

export default pirResolvers;
