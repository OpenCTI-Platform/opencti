import type { Resolvers } from '../../generated/graphql';
import type { AuthContext } from '../../types/user';
import { findCatalogRevisions, queryCatalogById, queryCatalogs, queryContractBySlug } from './catalog-domain';

const catalogResolver: Resolvers = {
  Query: {
    catalog: (_, { id }, context) => {
      return queryCatalogById(context, context.user, id);
    },
    catalogs: (_, _args, context) => {
      return queryCatalogs(context, context.user);
    },
    catalogsRevisions: (_: unknown, _args: Record<string, never>, context: AuthContext) => {
      return findCatalogRevisions(context, context.user!);
    },
    contract: (_, { slug }, context) => {
      return queryContractBySlug(context, context.user, slug);
    },
  },
};

export default catalogResolver;
