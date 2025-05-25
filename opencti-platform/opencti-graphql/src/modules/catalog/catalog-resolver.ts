import { findAll, findById } from './catalog-domain';
import type { Resolvers } from '../../generated/graphql';

const catalogResolver: Resolvers = {
  Query: {
    catalog: (_, { id }, context) => findById(context, context.user, id),
    catalogs: (_, args, context) => findAll(context, context.user),
  },
};

export default catalogResolver;
