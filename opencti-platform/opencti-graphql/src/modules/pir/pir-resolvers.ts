import type { Resolvers } from '../../generated/graphql';
import { deletePir, findAll, findById, pirAdd } from './pir-domain';
import { batchLoader } from '../../database/middleware';
import { batchCreators } from '../../domain/user';

const creatorsLoader = batchLoader(batchCreators);

const pirResolvers: Resolvers = {
  Query: {
    pir: (_, { id }, context) => findById(context, context.user, id),
    pirs: (_, args, context) => findAll(context, context.user, args),
  },
  PIR: {
    creators: (pir, _, context) => creatorsLoader.load(pir.creator_id, context, context.user),
  },
  Mutation: {
    pirAdd: (_, { input }, context) => pirAdd(context, context.user, input),
    pirDelete: (_, { id }, context) => deletePir(context, context.user, id),
  }
};

export default pirResolvers;
