import type { Resolvers } from '../../generated/graphql';
import { addPirDependency, deletePir, findAll, findById, pirAdd } from './pir-domain';
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
    pirAddDependency: (_, { id, input }, context) => addPirDependency(context, context.user, id, input),
  }
};

export default pirResolvers;
