import type { Resolvers } from '../../generated/graphql';
import { findAll, pirAdd } from './pir-domain';

const pirResolvers: Resolvers = {
  Query: {
    pirs: (_, args, context) => findAll(context, context.user, args),
  },
  Mutation: {
    pirAdd: (_, args, context) => pirAdd(context, context.user)
  }
};

export default pirResolvers;
