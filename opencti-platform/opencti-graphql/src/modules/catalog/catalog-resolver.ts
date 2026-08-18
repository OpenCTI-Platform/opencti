import { queryCatalogById, queryCatalogs, queryContractBySlug } from './catalog-domain';
import type { Resolvers } from '../../generated/graphql';

const catalogResolver: Resolvers = {
  Query: {
    catalog: (_, { id }, context) => {
      return queryCatalogById(context, context.user, id);
    },
    catalogs: (_, _args, context) => {
      return queryCatalogs(context, context.user);
    },
    contract: (_, { slug }, context) => {
      return queryContractBySlug(context, context.user, slug);
    },
  },
};

export default catalogResolver;
